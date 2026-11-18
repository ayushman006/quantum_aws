"""Tests for Phase 5 final polish: rich escaping, config validation, tag overrides, count expansion, and schema version."""

from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from pqlint.cli import app
from pqlint.config import Config
from pqlint.engine.scoring import evaluate_mosca_risk
from pqlint.model import ExposureType, Finding, Origin, Resource, ScanResult, Severity
from pqlint.parsers.terraform import parse_terraform_file

runner = CliRunner()


def test_config_validation_boundaries():
    """Verify Config validation bounds: crqc_years gt 0, shelf_life and migration ge 0."""
    with pytest.raises(ValidationError):
        Config(crqc_years=0)

    with pytest.raises(ValidationError):
        Config(crqc_years=-5)

    with pytest.raises(ValidationError):
        Config(shelf_life_years=-1)

    with pytest.raises(ValidationError):
        Config(migration_years=-1)

    # Valid boundary values
    cfg = Config(crqc_years=1, shelf_life_years=0, migration_years=0)
    assert cfg.crqc_years == 1
    assert cfg.shelf_life_years == 0
    assert cfg.migration_years == 0


def test_tag_override_shelf_life_pqlint_shelf_life():
    """Verify PQLint_Shelf_Life tag overrides global shelf life config."""
    res = Resource(
        type="aws_kms_key",
        name="tagged_key",
        origin=Origin.IAC,
        attributes={"tags": {"PQLint_Shelf_Life": "50"}},
    )
    finding = Finding(
        rule_id="PQL-KMS-001",
        rule_title="KMS Key",
        resource=res,
        severity=Severity.HIGH,
        exposure=ExposureType.CONFIDENTIALITY,
        message="Vulnerable key",
    )
    # Global config X=10, Y=3, Z=12. Without tag, 10+3=13 > 12 (at_risk=True).
    # If X tag was 5, 5+3=8 <= 12 (at_risk=False). Let's test with tag 50:
    scored = evaluate_mosca_risk(
        finding, Config(shelf_life_years=10, migration_years=3, crqc_years=12)
    )
    assert scored.mosca is not None
    assert scored.mosca.x == 50
    assert "X (50)" in scored.message

    # Test lowering X via tag so condition X + Y > Z becomes False
    res_low = Resource(
        type="aws_kms_key",
        name="low_x_key",
        origin=Origin.IAC,
        attributes={"tags": {"pqlint_shelf_life": "5"}},
    )
    finding_low = Finding(
        rule_id="PQL-KMS-001",
        rule_title="KMS Key",
        resource=res_low,
        severity=Severity.HIGH,
        exposure=ExposureType.CONFIDENTIALITY,
        message="Vulnerable key",
    )
    scored_low = evaluate_mosca_risk(
        finding_low, Config(shelf_life_years=10, migration_years=3, crqc_years=12)
    )
    assert scored_low.mosca is not None
    assert scored_low.mosca.x == 5
    assert scored_low.mosca.at_risk is False
    assert scored_low.severity == Severity.INFO


def test_tag_override_shelf_life_mosca_x():
    """Verify mosca_x tag (case-insensitive) overrides global shelf life config."""
    res = Resource(
        type="aws_kms_key",
        name="tagged_key",
        origin=Origin.IAC,
        attributes={"tags": {"MOSCA_X": 25}},
    )
    finding = Finding(
        rule_id="PQL-KMS-001",
        rule_title="KMS Key",
        resource=res,
        severity=Severity.HIGH,
        exposure=ExposureType.CONFIDENTIALITY,
        message="Vulnerable key",
    )
    scored = evaluate_mosca_risk(
        finding, Config(shelf_life_years=10, migration_years=3, crqc_years=12)
    )
    assert scored.mosca is not None
    assert scored.mosca.x == 25


def test_terraform_count_expansion_n_instances(tmp_path: Path):
    """Verify that count = N yields exactly N array-indexed Resource instances."""
    tf_file = tmp_path / "count_test.tf"
    tf_file.write_text(
        """
        resource "aws_kms_key" "multi_key" {
          count = 3
          customer_master_key_spec = "RSA_2048"
        }
        """,
        encoding="utf-8",
    )
    resources = parse_terraform_file(tf_file)
    assert len(resources) == 3
    names = [r.name for r in resources]
    assert names == ["multi_key[0]", "multi_key[1]", "multi_key[2]"]
    for r in resources:
        assert r.type == "aws_kms_key"
        assert r.attributes["customer_master_key_spec"] == "RSA_2048"


def test_terraform_count_expansion_zero(tmp_path: Path):
    """Verify that count = 0 yields zero Resource instances."""
    tf_file = tmp_path / "count_zero.tf"
    tf_file.write_text(
        """
        resource "aws_kms_key" "disabled_key" {
          count = 0
          customer_master_key_spec = "RSA_2048"
        }
        """,
        encoding="utf-8",
    )
    resources = parse_terraform_file(tf_file)
    assert len(resources) == 0


def test_terraform_count_expansion_absent_and_unresolvable(tmp_path: Path):
    """Verify that absent count or unresolvable count yields standard base name."""
    tf_file = tmp_path / "count_fallback.tf"
    tf_file.write_text(
        """
        resource "aws_kms_key" "single_key" {
          customer_master_key_spec = "RSA_2048"
        }
        resource "aws_kms_key" "unknown_count_key" {
          count = var.unresolved_count
          customer_master_key_spec = "RSA_2048"
        }
        """,
        encoding="utf-8",
    )
    resources = parse_terraform_file(tf_file)
    assert len(resources) == 2
    names = [r.name for r in resources]
    assert "single_key" in names
    assert "unknown_count_key" in names


def test_scan_result_schema_version():
    """Verify ScanResult contains schema_version '1.0.0'."""
    result = ScanResult()
    assert result.schema_version == "1.0.0"
    data = result.model_dump()
    assert data["schema_version"] == "1.0.0"


def test_markup_crash_prevention(tmp_path: Path):
    """Verify CLI does not crash when message contains literal brackets like [AES256]."""
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        """
        resource "aws_s3_bucket_server_side_encryption_configuration" "bucket" {
          rule {
            apply_server_side_encryption_by_default {
              sse_algorithm = "AES256"
            }
          }
        }
        """,
        encoding="utf-8",
    )
    result = runner.invoke(app, ["scan-iac", str(tmp_path)])
    assert result.exit_code == 0
    # Rule PQL-S3-001 message mentions AES256, verify it prints without Rich markup errors
    assert "PQL-S3-001" in result.output
