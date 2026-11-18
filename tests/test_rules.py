import pytest

from pqlint.engine.rules import (
    RuleEngine,
    evaluate_condition,
    evaluate_resource_against_rule,
    load_rules_from_dir,
    parse_rule_yaml,
)
from pqlint.model import UNKNOWN, ExposureType, Origin, Resource, Severity
from pqlint.parsers.terraform import parse_terraform_directory


@pytest.fixture
def sample_rule_yaml():
    return """id: PQL-KMS-001
title: Asymmetric KMS key uses quantum-vulnerable algorithm
resource_type: aws_kms_key
condition:
  attribute: customer_master_key_spec
  in: [RSA_2048, RSA_3072, RSA_4096, ECC_NIST_P256, ECC_NIST_P384, ECC_NIST_P521, ECC_SECG_P256K1]
exposure: authenticity
base_severity: high
message: "KMS key uses {value}, which is vulnerable to Shor's algorithm."
references:
  - "NIST FIPS 204 / NIST IR 8547"
remediation_ref: kms_asymmetric
"""


def test_yaml_parsing(sample_rule_yaml):
    parsed = parse_rule_yaml(sample_rule_yaml)
    assert parsed["id"] == "PQL-KMS-001"
    assert parsed["title"] == "Asymmetric KMS key uses quantum-vulnerable algorithm"
    assert parsed["resource_type"] == "aws_kms_key"
    assert parsed["condition"]["attribute"] == "customer_master_key_spec"
    assert "RSA_2048" in parsed["condition"]["in"]
    assert "ECC_SECG_P256K1" in parsed["condition"]["in"]
    assert parsed["exposure"] == "authenticity"
    assert parsed["base_severity"] == "high"
    assert "{value}" in parsed["message"]
    assert parsed["references"] == ["NIST FIPS 204 / NIST IR 8547"]
    assert parsed["remediation_ref"] == "kms_asymmetric"


def test_load_all_four_initial_rules():
    rules = load_rules_from_dir()
    rule_ids = {r["id"] for r in rules}
    assert "PQL-KMS-001" in rule_ids
    assert "PQL-ACM-001" in rule_ids
    assert "PQL-ALB-001" in rule_ids
    assert "PQL-S3-001" in rule_ids


def test_evaluate_kms_vulnerable_rsa():
    engine = RuleEngine()
    vulnerable_key = Resource(
        type="aws_kms_key",
        name="my_vulnerable_rsa_key",
        attributes={"customer_master_key_spec": "RSA_2048"},
        source_location="main.tf:10",
        origin=Origin.IAC,
    )

    findings = engine.evaluate([vulnerable_key])
    assert len(findings) == 1
    finding = findings[0]

    assert finding.rule_id == "PQL-KMS-001"
    assert finding.severity == Severity.HIGH
    assert finding.exposure == ExposureType.AUTHENTICITY
    assert finding.resource.name == "my_vulnerable_rsa_key"
    assert "RSA_2048" in finding.message
    assert finding.remediation_ref == "kms_asymmetric"
    assert "NIST FIPS 204 / NIST IR 8547" in finding.references


def test_evaluate_kms_vulnerable_ecc():
    engine = RuleEngine()
    vulnerable_key = Resource(
        type="aws_kms_key",
        name="my_vulnerable_ecc_key",
        attributes={"customer_master_key_spec": "ECC_NIST_P384"},
        source_location="main.tf:20",
        origin=Origin.IAC,
    )

    findings = engine.evaluate([vulnerable_key])
    assert len(findings) == 1
    assert "ECC_NIST_P384" in findings[0].message


def test_evaluate_kms_safe_symmetric():
    engine = RuleEngine()
    safe_key = Resource(
        type="aws_kms_key",
        name="my_safe_symmetric_key",
        attributes={"customer_master_key_spec": "SYMMETRIC_DEFAULT"},
        source_location="main.tf:30",
        origin=Origin.IAC,
    )

    findings = engine.evaluate([safe_key])
    assert len(findings) == 0


def test_evaluate_acm_vulnerable_cert():
    engine = RuleEngine()
    cert = Resource(
        type="aws_acm_certificate",
        name="api_cert",
        attributes={"key_algorithm": "RSA_2048"},
        origin=Origin.IAC,
    )
    findings = engine.evaluate([cert])
    assert len(findings) == 1
    assert findings[0].rule_id == "PQL-ACM-001"
    assert findings[0].severity == Severity.HIGH
    assert "RSA_2048" in findings[0].message


def test_evaluate_alb_non_pq_policy():
    engine = RuleEngine()
    listener = Resource(
        type="aws_lb_listener",
        name="front_end",
        attributes={"ssl_policy": "ELBSecurityPolicy-2016-08"},
        origin=Origin.IAC,
    )
    findings = engine.evaluate([listener])
    assert len(findings) == 1
    assert findings[0].rule_id == "PQL-ALB-001"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].exposure == ExposureType.CONFIDENTIALITY


def test_evaluate_alb_pq_hybrid_policy():
    engine = RuleEngine()
    listener = Resource(
        type="aws_lb_listener",
        name="front_end_pq",
        attributes={"ssl_policy": "ELBSecurityPolicy-TLS13-1-3-PQ-2023-06"},
        origin=Origin.IAC,
    )
    findings = engine.evaluate([listener])
    assert len(findings) == 0


def test_evaluate_s3_standard_aes256_nested():
    engine = RuleEngine()
    s3_res = Resource(
        type="aws_s3_bucket_server_side_encryption_configuration",
        name="bucket_enc",
        attributes={
            "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]
        },
        origin=Origin.IAC,
    )
    findings = engine.evaluate([s3_res])
    assert len(findings) == 1
    assert findings[0].rule_id == "PQL-S3-001"
    assert findings[0].severity == Severity.INFO


def test_terraform_directory_parser():
    resources = parse_terraform_directory("examples/terraform")
    assert len(resources) == 4
    types = {r.type for r in resources}
    assert "aws_kms_key" in types
    assert "aws_acm_certificate" in types
    assert "aws_lb_listener" in types
    assert "aws_s3_bucket_server_side_encryption_configuration" in types


def test_evaluate_condition_exists_true():
    """Verify exists: true returns True when present, False when None, and None when UNKNOWN."""
    condition = {"attribute": "kms_key_id", "exists": True}

    # Present attribute
    matched, val = evaluate_condition(
        condition, {"kms_key_id": "arn:aws:kms:us-east-1:123:key/abc"}
    )
    assert matched is True
    assert val == "arn:aws:kms:us-east-1:123:key/abc"

    # Absent attribute
    matched, val = evaluate_condition(condition, {})
    assert matched is False
    assert val is None

    # Explicit None attribute
    matched, val = evaluate_condition(condition, {"kms_key_id": None})
    assert matched is False
    assert val is None

    # UNKNOWN attribute
    matched, val = evaluate_condition(condition, {"kms_key_id": UNKNOWN})
    assert matched is None
    assert val == UNKNOWN


def test_evaluate_condition_exists_false():
    """Verify exists: false returns True when None, False when present, and None when UNKNOWN."""
    condition = {"attribute": "kms_key_id", "exists": False}

    # Absent attribute
    matched, val = evaluate_condition(condition, {})
    assert matched is True
    assert val is None

    # Explicit None attribute
    matched, val = evaluate_condition(condition, {"kms_key_id": None})
    assert matched is True
    assert val is None

    # Present attribute
    matched, val = evaluate_condition(
        condition, {"kms_key_id": "arn:aws:kms:us-east-1:123:key/abc"}
    )
    assert matched is False
    assert val == "arn:aws:kms:us-east-1:123:key/abc"

    # UNKNOWN attribute
    matched, val = evaluate_condition(condition, {"kms_key_id": UNKNOWN})
    assert matched is None
    assert val == UNKNOWN


def test_evaluate_condition_not_equals():
    """Verify not_equals / ne returns False on match, True on mismatch, False when None, and None when UNKNOWN."""
    # Test not_equals
    condition_ne = {"attribute": "sse_algorithm", "not_equals": "AES256"}

    # Target match -> not equal is False
    matched, val = evaluate_condition(condition_ne, {"sse_algorithm": "AES256"})
    assert matched is False
    assert val == "AES256"

    # Type coercion match (e.g. integer to string or vice versa) -> not equal is False
    cond_port = {"attribute": "port", "not_equals": "443"}
    matched, val = evaluate_condition(cond_port, {"port": 443})
    assert matched is False

    # Target mismatch -> not equal is True
    matched, val = evaluate_condition(condition_ne, {"sse_algorithm": "aws:kms"})
    assert matched is True
    assert val == "aws:kms"

    # Missing attribute (None) -> False (missing attributes cannot be not equal)
    matched, val = evaluate_condition(condition_ne, {})
    assert matched is False
    assert val is None

    # UNKNOWN attribute -> None
    matched, val = evaluate_condition(condition_ne, {"sse_algorithm": UNKNOWN})
    assert matched is None
    assert val == UNKNOWN

    # Test 'ne' alias
    condition_alias = {"attribute": "sse_algorithm", "ne": "AES256"}
    matched, val = evaluate_condition(condition_alias, {"sse_algorithm": "AES256"})
    assert matched is False
    matched, val = evaluate_condition(condition_alias, {"sse_algorithm": "aws:kms"})
    assert matched is True


def test_evaluate_rule_with_exists_and_not_equals():
    """Integration test evaluating full rules using exists and not_equals operators."""
    rule_exists = {
        "id": "PQL-TEST-EXISTS",
        "title": "Unencrypted bucket without KMS",
        "resource_type": "aws_s3_bucket",
        "condition": {"attribute": "kms_master_key_id", "exists": False},
        "base_severity": "high",
        "exposure": "confidentiality",
        "message": "Bucket lacks KMS master key",
    }

    # Matches condition (kms_master_key_id does not exist) -> Finding generated
    res_vulnerable = Resource(type="aws_s3_bucket", name="b1", attributes={}, origin=Origin.IAC)
    finding = evaluate_resource_against_rule(res_vulnerable, rule_exists)
    assert finding is not None
    assert finding.severity == Severity.HIGH

    # Safe resource (kms_master_key_id exists) -> No finding
    res_safe = Resource(
        type="aws_s3_bucket",
        name="b2",
        attributes={"kms_master_key_id": "arn:aws:kms:us-east-1:123:key/k1"},
        origin=Origin.IAC,
    )
    assert evaluate_resource_against_rule(res_safe, rule_exists) is None

    # UNKNOWN resource -> Finding with Severity.UNKNOWN
    res_unknown = Resource(
        type="aws_s3_bucket",
        name="b3",
        attributes={"kms_master_key_id": UNKNOWN},
        origin=Origin.IAC,
    )
    finding_unknown = evaluate_resource_against_rule(res_unknown, rule_exists)
    assert finding_unknown is not None
    assert finding_unknown.severity == Severity.UNKNOWN
