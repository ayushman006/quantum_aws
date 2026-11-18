"""Unit and integration tests for Phase 2: UNKNOWN variable resolution and provider defaults."""

from pathlib import Path

from typer.testing import CliRunner

from pqlint.cli import app
from pqlint.config import Config
from pqlint.engine.rules import RuleEngine
from pqlint.engine.scoring import score_findings
from pqlint.model import (
    UNKNOWN,
    ExposureType,
    Finding,
    Origin,
    Resource,
    ScanResult,
    Severity,
    is_unknown,
)
from pqlint.parsers.defaults import apply_provider_defaults
from pqlint.parsers.terraform import parse_terraform_directory, parse_terraform_file
from pqlint.redaction import redact_scan_result


def test_is_unknown_helper():
    assert is_unknown(UNKNOWN)
    assert is_unknown("<UNKNOWN>")
    assert is_unknown("UNKNOWN")
    assert is_unknown("${var.foo}")
    assert is_unknown("${local.bar}")
    assert is_unknown("${module.vpc.id}")
    assert is_unknown("${data.aws_kms_key.k.arn}")
    assert is_unknown("var.unresolved")
    assert is_unknown("local.unresolved")
    assert not is_unknown("RSA_2048")
    assert not is_unknown(None)
    assert not is_unknown(12345)
    assert not is_unknown(["RSA_2048"])


def test_provider_defaults_kms_key():
    attrs = apply_provider_defaults("aws_kms_key", {})
    assert attrs["customer_master_key_spec"] == "SYMMETRIC_DEFAULT"

    # Explicit value is not overwritten
    explicit = {"customer_master_key_spec": "RSA_4096"}
    assert (
        apply_provider_defaults("aws_kms_key", explicit)["customer_master_key_spec"] == "RSA_4096"
    )


def test_provider_defaults_acm_certificate():
    attrs = apply_provider_defaults("aws_acm_certificate", {})
    assert attrs["key_algorithm"] == "RSA_2048"

    explicit = {"key_algorithm": "EC_prime256v1"}
    assert (
        apply_provider_defaults("aws_acm_certificate", explicit)["key_algorithm"] == "EC_prime256v1"
    )


def test_provider_defaults_alb_https_listener():
    # HTTPS listener missing ssl_policy gets default
    attrs = apply_provider_defaults("aws_lb_listener", {"protocol": "HTTPS"})
    assert attrs["ssl_policy"] == "ELBSecurityPolicy-2016-08"

    # TLS listener missing ssl_policy gets default
    attrs_tls = apply_provider_defaults("aws_lb_listener", {"protocol": "TLS"})
    assert attrs_tls["ssl_policy"] == "ELBSecurityPolicy-2016-08"

    # HTTP listener does not get ssl_policy default
    attrs_http = apply_provider_defaults("aws_lb_listener", {"protocol": "HTTP"})
    assert "ssl_policy" not in attrs_http


def test_provider_defaults_s3_encryption():
    attrs = apply_provider_defaults("aws_s3_bucket_server_side_encryption_configuration", {})
    assert (
        attrs["rule"][0]["apply_server_side_encryption_by_default"][0]["sse_algorithm"] == "AES256"
    )


def test_parse_terraform_with_variable_defaults(tmp_path: Path):
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        """
variable "key_spec" {
  default = "RSA_2048"
}

resource "aws_kms_key" "k" {
  customer_master_key_spec = var.key_spec
}
""",
        encoding="utf-8",
    )
    resources = parse_terraform_file(tf_file)
    assert len(resources) == 1
    assert resources[0].attributes["customer_master_key_spec"] == "RSA_2048"


def test_parse_terraform_with_unresolved_variable(tmp_path: Path):
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        """
variable "unresolved_spec" {
  type = string
}

resource "aws_kms_key" "k" {
  customer_master_key_spec = var.unresolved_spec
}
""",
        encoding="utf-8",
    )
    resources = parse_terraform_file(tf_file)
    assert len(resources) == 1
    assert resources[0].attributes["customer_master_key_spec"] == UNKNOWN


def test_parse_terraform_with_locals_chaining(tmp_path: Path):
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        """
variable "base_spec" {
  default = "ECC_NIST_P384"
}

locals {
  alias_spec = var.base_spec
  final_spec = local.alias_spec
}

resource "aws_kms_key" "k" {
  customer_master_key_spec = local.final_spec
}
""",
        encoding="utf-8",
    )
    resources = parse_terraform_file(tf_file)
    assert len(resources) == 1
    assert resources[0].attributes["customer_master_key_spec"] == "ECC_NIST_P384"


def test_parse_terraform_multi_file_directory(tmp_path: Path):
    vars_file = tmp_path / "variables.tf"
    vars_file.write_text(
        """
variable "cert_algo" {
  default = "RSA_4096"
}
""",
        encoding="utf-8",
    )

    locals_file = tmp_path / "locals.tf"
    locals_file.write_text(
        """
locals {
  resolved_cert_algo = var.cert_algo
}
""",
        encoding="utf-8",
    )

    main_file = tmp_path / "main.tf"
    main_file.write_text(
        """
resource "aws_acm_certificate" "cert" {
  domain_name   = "example.com"
  key_algorithm = local.resolved_cert_algo
}
""",
        encoding="utf-8",
    )

    resources = parse_terraform_directory(tmp_path)
    assert len(resources) == 1
    assert resources[0].attributes["key_algorithm"] == "RSA_4096"


def test_rule_engine_prevents_silent_pass_for_unknown_in_condition():
    """When an attribute in an 'in' condition is UNKNOWN, yield a Finding with Severity.UNKNOWN."""
    engine = RuleEngine()
    resource = Resource(
        type="aws_kms_key",
        name="unknown_key",
        attributes={"customer_master_key_spec": UNKNOWN},
        origin=Origin.IAC,
    )
    findings = engine.evaluate([resource])
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "PQL-KMS-001"
    assert f.severity == Severity.UNKNOWN
    assert "could not be evaluated" in f.message
    assert "customer_master_key_spec" in f.message
    assert engine.unresolved_count == 1


def test_rule_engine_prevents_false_flag_for_unknown_not_in_condition():
    """When an attribute in a 'not_in' condition is UNKNOWN, yield Severity.UNKNOWN instead of flagging as vulnerable."""
    engine = RuleEngine()
    listener = Resource(
        type="aws_lb_listener",
        name="unknown_alb",
        attributes={"protocol": "HTTPS", "ssl_policy": UNKNOWN},
        origin=Origin.IAC,
    )
    findings = engine.evaluate([listener])
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "PQL-ALB-001"
    # Must NOT be CRITICAL (base severity of alb rule); must be UNKNOWN
    assert f.severity == Severity.UNKNOWN
    assert "could not be evaluated" in f.message
    assert engine.unresolved_count == 1


def test_provider_defaults_flag_alb_missing_ssl_policy():
    """If aws_lb_listener is HTTPS and misses ssl_policy, default to ELBSecurityPolicy-2016-08 and flag as CRITICAL."""
    engine = RuleEngine()
    listener = Resource(
        type="aws_lb_listener",
        name="alb_default_policy",
        attributes={"protocol": "HTTPS"},  # ssl_policy omitted
        origin=Origin.IAC,
    )
    findings = engine.evaluate([listener])
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "PQL-ALB-001"
    assert f.severity == Severity.CRITICAL
    assert "ELBSecurityPolicy-2016-08" in f.message


def test_provider_defaults_kms_missing_spec_is_safe():
    """If aws_kms_key misses customer_master_key_spec, default to SYMMETRIC_DEFAULT (safe, 0 findings)."""
    engine = RuleEngine()
    key = Resource(
        type="aws_kms_key",
        name="kms_default_symmetric",
        attributes={},  # customer_master_key_spec omitted
        origin=Origin.IAC,
    )
    findings = engine.evaluate([key])
    assert len(findings) == 0


def test_mosca_scoring_preserves_unknown_severity():
    finding = Finding(
        rule_id="PQL-KMS-001",
        rule_title="KMS",
        resource=Resource(type="aws_kms_key", name="k", origin=Origin.IAC),
        severity=Severity.UNKNOWN,
        exposure=ExposureType.AUTHENTICITY,
        message="Attribute unresolved",
    )
    config = Config(
        shelf_life_years=10, migration_years=3, crqc_years=50
    )  # Y < Z would downgrade if evaluated
    scored = score_findings([finding], config)
    assert scored[0].severity == Severity.UNKNOWN
    assert "Mosca risk evaluation skipped" in scored[0].message


def test_redaction_preserves_unknown_scan_result():
    resource = Resource(
        type="aws_kms_key",
        name="k",
        attributes={"account_id": "123456789012", "spec": UNKNOWN},
        origin=Origin.IAC,
    )
    finding = Finding(
        rule_id="PQL-KMS-001",
        rule_title="KMS",
        resource=resource,
        severity=Severity.UNKNOWN,
        exposure=ExposureType.AUTHENTICITY,
        message="Attribute in account 123456789012 could not be resolved",
    )
    sr = ScanResult(resources=[resource], findings=[finding], unresolved_count=1)
    redacted = redact_scan_result(sr)

    assert "123456789012" not in redacted.findings[0].message
    assert "ACCT-1" in redacted.findings[0].message
    assert redacted.findings[0].severity == Severity.UNKNOWN
    assert redacted.unresolved_count == 1


def test_cli_summary_reports_unresolved_count(tmp_path: Path):
    runner = CliRunner()
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        """
variable "unresolved_spec" {
  type = string
}

resource "aws_kms_key" "k" {
  customer_master_key_spec = var.unresolved_spec
}
""",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan-iac", str(tmp_path)])
    assert result.exit_code == 1
    assert "1 attributes could not be resolved" in result.output
    assert "UNKNOWN" in result.output
