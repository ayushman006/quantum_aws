"""Tests for Milestone 3: Support matrix, remediation suggestions, parser robustness, and dynamic exposure."""

from pathlib import Path

from pqlint.data import rules as rules_data_mod  # type: ignore # noqa: F401
from pqlint.engine.remediation import DEFAULT_SUPPORT_MATRIX_PATH, suggest_remediation
from pqlint.engine.rules import RuleEngine, evaluate_resource_against_rule
from pqlint.model import ExposureType, Finding, Origin, Resource, Severity
from pqlint.parsers.terraform import parse_terraform_directory


def test_parser_skips_terraform_and_git_directories(tmp_path: Path):
    """Verify that .terraform and .git directories are explicitly ignored during traversal."""
    root_tf = tmp_path / "main.tf"
    root_tf.write_text(
        'resource "aws_kms_key" "valid" { customer_master_key_spec = "RSA_2048" }',
        encoding="utf-8",
    )

    tf_dir = tmp_path / ".terraform" / "modules"
    tf_dir.mkdir(parents=True)
    (tf_dir / "ignored.tf").write_text(
        'resource "aws_kms_key" "ignored" { customer_master_key_spec = "RSA_2048" }',
        encoding="utf-8",
    )

    git_dir = tmp_path / ".git" / "hooks"
    git_dir.mkdir(parents=True)
    (git_dir / "git_ignored.tf").write_text(
        'resource "aws_kms_key" "git_ignored" { customer_master_key_spec = "RSA_2048" }',
        encoding="utf-8",
    )

    resources = parse_terraform_directory(tmp_path)
    assert len(resources) == 1
    assert resources[0].name == "valid"


def test_parser_captures_unparseable_file_warning(tmp_path: Path):
    """Verify file-read exceptions are captured in warnings and not silently swallowed."""
    good_tf = tmp_path / "valid.tf"
    good_tf.write_text('resource "aws_kms_key" "valid" {}', encoding="utf-8")

    bad_tf = tmp_path / "corrupt.tf"
    bad_tf.write_text("resource aws_kms_key { syntax_error {{", encoding="utf-8")

    warnings: list[str] = []
    resources = parse_terraform_directory(tmp_path, warnings=warnings)

    assert len(resources) == 1
    assert any("corrupt.tf" in w for w in warnings)


def test_kms_dynamic_exposure_encrypt_decrypt():
    """Verify KMS key with key_usage='ENCRYPT_DECRYPT' evaluates to CONFIDENTIALITY exposure."""
    kms_rule = {
        "id": "PQL-KMS-001",
        "title": "Asymmetric KMS key uses quantum-vulnerable algorithm",
        "resource_type": "aws_kms_key",
        "condition": {
            "attribute": "customer_master_key_spec",
            "in": ["RSA_2048", "RSA_3072", "RSA_4096"],
        },
        "exposure": "authenticity",
        "base_severity": "high",
        "message": "KMS key uses {value}.",
        "remediation_ref": "kms_asymmetric",
    }
    res = Resource(
        type="aws_kms_key",
        name="crypto_key",
        origin=Origin.IAC,
        attributes={
            "customer_master_key_spec": "RSA_2048",
            "key_usage": "ENCRYPT_DECRYPT",
        },
    )
    finding = evaluate_resource_against_rule(res, kms_rule)
    assert finding is not None
    assert finding.exposure == ExposureType.CONFIDENTIALITY


def test_kms_dynamic_exposure_sign_verify_and_default():
    """Verify KMS key without ENCRYPT_DECRYPT defaults to AUTHENTICITY exposure."""
    kms_rule = {
        "id": "PQL-KMS-001",
        "title": "Asymmetric KMS key uses quantum-vulnerable algorithm",
        "resource_type": "aws_kms_key",
        "condition": {
            "attribute": "customer_master_key_spec",
            "in": ["RSA_2048", "RSA_3072", "RSA_4096"],
        },
        "exposure": "authenticity",
        "base_severity": "high",
        "message": "KMS key uses {value}.",
        "remediation_ref": "kms_asymmetric",
    }

    # Case 1: key_usage is explicitly SIGN_VERIFY
    res_sign = Resource(
        type="aws_kms_key",
        name="signing_key",
        origin=Origin.IAC,
        attributes={
            "customer_master_key_spec": "RSA_2048",
            "key_usage": "SIGN_VERIFY",
        },
    )
    finding_sign = evaluate_resource_against_rule(res_sign, kms_rule)
    assert finding_sign is not None
    assert finding_sign.exposure == ExposureType.AUTHENTICITY

    # Case 2: key_usage is omitted
    res_default = Resource(
        type="aws_kms_key",
        name="default_key",
        origin=Origin.IAC,
        attributes={"customer_master_key_spec": "RSA_2048"},
    )
    finding_default = evaluate_resource_against_rule(res_default, kms_rule)
    assert finding_default is not None
    assert finding_default.exposure == ExposureType.AUTHENTICITY


def test_s3_rule_base_severity_is_info():
    """Verify that s3.yaml has base_severity set to info (K3)."""
    rules_dir = Path(__file__).resolve().parent.parent / "src" / "pqlint" / "data" / "rules"
    engine = RuleEngine(rules_dir)
    engine.load_rules()
    s3_rules = [r for r in engine.rules if r.get("id") == "PQL-S3-001"]
    assert len(s3_rules) == 1
    assert s3_rules[0].get("base_severity") == "info"


def test_suggest_remediation_nlb_pq_tls():
    """Verify suggest_remediation returns verified upgrade path for nlb_pq_tls."""
    finding = Finding(
        rule_id="PQL-ALB-001",
        rule_title="ALB Listener lacks post-quantum hybrid TLS policy",
        resource=Resource(type="aws_lb_listener", name="https", origin=Origin.IAC),
        severity=Severity.HIGH,
        exposure=ExposureType.CONFIDENTIALITY,
        message="Non-PQ TLS listener",
        remediation_ref="nlb_pq_tls",
    )
    suggestion = suggest_remediation(finding)
    assert suggestion is not None
    assert "ELBSecurityPolicy-TLS13-1-3-PQ-2023-06" in suggestion


def test_suggest_remediation_unmapped_ref():
    """Verify suggest_remediation returns None when remediation_ref is absent or unmapped."""
    finding_no_ref = Finding(
        rule_id="PQL-TEST-001",
        rule_title="Test finding",
        resource=Resource(type="aws_test", name="test", origin=Origin.IAC),
        severity=Severity.LOW,
        exposure=ExposureType.AUTHENTICITY,
        message="No ref",
        remediation_ref=None,
    )
    assert suggest_remediation(finding_no_ref) is None

    finding_unknown_ref = Finding(
        rule_id="PQL-TEST-002",
        rule_title="Test finding",
        resource=Resource(type="aws_test", name="test", origin=Origin.IAC),
        severity=Severity.LOW,
        exposure=ExposureType.AUTHENTICITY,
        message="Unknown ref",
        remediation_ref="non_existent_policy_ref",
    )
    assert suggest_remediation(finding_unknown_ref) is None


def test_support_matrix_yaml_structure_and_dates():
    """Verify aws_pq_support.yaml contains nlb_pq_tls with required policies and 2026-11-17 date."""
    assert DEFAULT_SUPPORT_MATRIX_PATH.exists()
    import yaml

    data = yaml.safe_load(DEFAULT_SUPPORT_MATRIX_PATH.read_text(encoding="utf-8"))
    assert "nlb_pq_tls" in data
    nlb_entry = data["nlb_pq_tls"]
    assert nlb_entry["verified_date"] == "2026-11-17"
    assert "ELBSecurityPolicy-TLS13-1-3-PQ-2023-06" in nlb_entry["policies"]
    assert "ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06" in nlb_entry["policies"]
    assert "reference" in nlb_entry
