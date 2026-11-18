from unittest.mock import patch

import pytest

from pqlint.errors import RedactionLeakError
from pqlint.model import ExposureType, Finding, Origin, Resource, ScanResult, Severity
from pqlint.redaction import (
    ARN_ACCOUNT_PATTERN,
    redact_findings,
    redact_scan_result,
)


def test_arn_regex_matches_various_arn_structures():
    test_cases = [
        ("arn:aws:kms:us-east-1:123456789012:key/abc-123", "123456789012"),
        ("arn:aws:iam::111222333444:role/AdminRole", "111222333444"),
        ("arn:aws:*:*:555666777888:*", "555666777888"),
        ("arn:aws-us-gov:s3:us-gov-west-1:999888777666:accesspoint/test", "999888777666"),
        (
            "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/x/y",
            "123456789012",
        ),
    ]

    for arn_str, expected_acct in test_cases:
        match = ARN_ACCOUNT_PATTERN.search(arn_str)
        assert match is not None, f"Failed to match ARN: {arn_str}"
        assert match.group(2) == expected_acct


def test_tolerant_arn_with_terraform_interpolations():
    """Verify tolerant ARN matching handles Terraform variable interpolations."""
    interpolated_arn = "arn:aws:kms:${var.region}:123456789012:key/abc-123"
    resource = Resource(
        type="aws_kms_key",
        name="interpolated_key",
        attributes={"arn": interpolated_arn},
        origin=Origin.IAC,
    )
    finding = Finding(
        rule_id="PQL-KMS-001",
        rule_title="KMS",
        resource=resource,
        severity=Severity.HIGH,
        exposure=ExposureType.AUTHENTICITY,
        message=f"Key {interpolated_arn} uses vulnerable algorithm",
    )
    scan_result = ScanResult(findings=[finding], resources=[resource])
    redacted = redact_scan_result(scan_result)

    assert "123456789012" not in redacted.findings[0].message
    assert "arn:aws:kms:${var.region}:ACCT-1:key/abc-123" in redacted.findings[0].message
    assert redacted.resources[0].attributes["arn"] == "arn:aws:kms:${var.region}:ACCT-1:key/abc-123"


def test_integer_attribute_redaction():
    """Verify 12-digit integers parsed from HCL are converted and redacted to ACCT-X."""
    resource = Resource(
        type="aws_kms_key",
        name="int_key",
        attributes={
            "account_id": 123456789012,
            "nested": {"target_account": 987654321098},
        },
        origin=Origin.IAC,
    )
    scan_result = ScanResult(resources=[resource])
    redacted = redact_scan_result(scan_result)

    # 123456789012 < 987654321098 alphanumerically
    assert redacted.resources[0].attributes["account_id"] == "ACCT-1"
    assert redacted.resources[0].attributes["nested"]["target_account"] == "ACCT-2"
    # Ensure original input was not mutated
    assert resource.attributes["account_id"] == 123456789012


def test_sorting_determinism():
    """Verify alphanumeric sorting guarantees identical mapping regardless of discovery order."""
    # Order A: 987654321098 discovered first, then 123456789012
    r_a1 = Resource(
        type="t", name="r1", attributes={"account_id": "987654321098"}, origin=Origin.IAC
    )
    r_a2 = Resource(
        type="t", name="r2", attributes={"account_id": "123456789012"}, origin=Origin.IAC
    )
    res_a = redact_scan_result(ScanResult(resources=[r_a1, r_a2]))

    # Order B: 123456789012 discovered first, then 987654321098
    r_b1 = Resource(
        type="t", name="r2", attributes={"account_id": "123456789012"}, origin=Origin.IAC
    )
    r_b2 = Resource(
        type="t", name="r1", attributes={"account_id": "987654321098"}, origin=Origin.IAC
    )
    res_b = redact_scan_result(ScanResult(resources=[r_b1, r_b2]))

    # In both cases, 123456789012 MUST map to ACCT-1 and 987654321098 to ACCT-2
    assert res_a.resources[0].attributes["account_id"] == "ACCT-2"  # 987654321098
    assert res_a.resources[1].attributes["account_id"] == "ACCT-1"  # 123456789012

    assert res_b.resources[0].attributes["account_id"] == "ACCT-1"  # 123456789012
    assert res_b.resources[1].attributes["account_id"] == "ACCT-2"  # 987654321098


def test_embedded_json_string_redaction():
    """Verify account IDs inside embedded JSON policy strings are redacted."""
    json_policy = '{"Version":"2012-10-17","Statement":[{"Principal":{"AWS":["arn:aws:iam::123456789012:root","987654321098"]}}]}'
    resource = Resource(
        type="aws_kms_key",
        name="policy_key",
        attributes={"policy": json_policy},
        origin=Origin.IAC,
    )
    scan_result = ScanResult(resources=[resource])
    redacted = redact_scan_result(scan_result)

    redacted_policy = redacted.resources[0].attributes["policy"]
    assert "123456789012" not in redacted_policy
    assert "987654321098" not in redacted_policy
    assert "ACCT-1" in redacted_policy
    assert "ACCT-2" in redacted_policy


def test_epoch_ms_13digit_preservation():
    """Verify 13-digit epoch-ms numbers and non-account numbers are preserved, while 12-digit numbers are masked."""
    resource = Resource(
        type="aws_kms_key",
        name="key_with_timestamp",
        attributes={
            "created_timestamp": "202611142045",
            "epoch_ms": 1700000000000,
            "account_id": "123456789012",
        },
        origin=Origin.IAC,
    )
    scan_result = ScanResult(resources=[resource])
    redacted = redact_scan_result(scan_result)

    attrs = redacted.resources[0].attributes
    # Account ID and 12-digit number are redacted
    assert attrs["account_id"] == "ACCT-1"
    assert attrs["created_timestamp"] == "ACCT-2"
    # 13-digit epoch timestamp is preserved
    assert attrs["epoch_ms"] == 1700000000000


def test_fail_closed_leak_guard_raises_redaction_leak_error():
    """Verify fail-closed leak guard aborts execution if an account ID remains in serialized output."""
    resource = Resource(
        type="aws_kms_key",
        name="key-leak",
        attributes={"arn": "arn:aws:kms:us-east-1:123456789012:key/leak"},
        origin=Origin.IAC,
    )
    finding = Finding(
        rule_id="PQL-KMS-001",
        rule_title="KMS",
        resource=resource,
        severity=Severity.HIGH,
        exposure=ExposureType.AUTHENTICITY,
        message="KMS key in arn:aws:kms:us-east-1:123456789012:key/leak",
    )
    scan_result = ScanResult(findings=[finding])

    # Simulate an engine bug where redaction fails to replace the ID
    with patch("pqlint.redaction._redact_value", lambda val, m, key_name=None: val):
        with pytest.raises(RedactionLeakError) as exc_info:
            redact_scan_result(scan_result)
        # Assert raw ID is NOT in the error message (Rule 4 & R7)
        assert "123456789012" not in str(exc_info.value)


def test_redact_scan_result_wrapper():
    """Verify ScanResult wrapper redacts resources, findings, and warnings comprehensively."""
    r = Resource(
        type="aws_kms_key",
        name="k1",
        attributes={"arn": "arn:aws:kms:us-east-1:123456789012:key/k1"},
        origin=Origin.IAC,
    )
    f = Finding(
        rule_id="PQL-KMS-001",
        rule_title="KMS",
        resource=r,
        severity=Severity.HIGH,
        exposure=ExposureType.AUTHENTICITY,
        message="Key in 123456789012",
    )
    sr = ScanResult(resources=[r], findings=[f], warnings=["Warning for account 123456789012"])
    redacted = redact_scan_result(sr)

    assert "123456789012" not in redacted.findings[0].message
    assert "123456789012" not in redacted.resources[0].attributes["arn"]
    assert "123456789012" not in redacted.warnings[0]
    assert "ACCT-1" in redacted.findings[0].message
    assert "ACCT-1" in redacted.resources[0].attributes["arn"]
    assert "ACCT-1" in redacted.warnings[0]
    # Input was not mutated
    assert "123456789012" in sr.findings[0].message


def test_redact_findings_basic():
    original_arn = "arn:aws:kms:us-east-1:123456789012:key/a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    resource = Resource(
        type="aws_kms_key",
        name="key-123456789012",
        source_location="accounts/123456789012/main.tf:10",
        provider_id=original_arn,
        attributes={
            "arn": original_arn,
            "description": "KMS key in 123456789012",
            "tags": {"Environment": "prod", "Account": "123456789012"},
        },
        origin=Origin.IAC,
    )
    finding = Finding(
        rule_id="PQL-KMS-001",
        rule_title="Asymmetric KMS key uses quantum-vulnerable algorithm",
        resource=resource,
        severity=Severity.HIGH,
        exposure=ExposureType.AUTHENTICITY,
        message=f"KMS key {original_arn} uses RSA_2048 in account 123456789012.",
    )

    redacted = redact_findings([finding], enabled=True)

    assert len(redacted) == 1
    rf = redacted[0]

    # Verify account ID was masked with ACCT-1
    assert "123456789012" not in rf.message
    assert "arn:aws:kms:us-east-1:ACCT-1:key/a1b2c3d4-e5f6-7890-abcd-ef1234567890" in rf.message
    assert "account ACCT-1" in rf.message

    assert rf.resource.name == "key-ACCT-1"
    assert rf.resource.source_location == "accounts/ACCT-1/main.tf:10"
    assert (
        rf.resource.provider_id
        == "arn:aws:kms:us-east-1:ACCT-1:key/a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    )
    assert (
        rf.resource.attributes["arn"]
        == "arn:aws:kms:us-east-1:ACCT-1:key/a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    )
    assert rf.resource.attributes["description"] == "KMS key in ACCT-1"
    assert rf.resource.attributes["tags"]["Account"] == "ACCT-1"

    # Verify original finding was NOT mutated (deep copy contract)
    assert "123456789012" in finding.message
    assert finding.resource.name == "key-123456789012"
    assert finding.resource.attributes["arn"] == original_arn


def test_deterministic_multi_account_placeholders():
    f1 = Finding(
        rule_id="PQL-KMS-001",
        rule_title="KMS",
        resource=Resource(
            type="aws_kms_key",
            name="k1",
            attributes={"arn": "arn:aws:kms:us-east-1:111111111111:key/1"},
            origin=Origin.IAC,
        ),
        severity=Severity.HIGH,
        exposure=ExposureType.AUTHENTICITY,
        message="Key in arn:aws:kms:us-east-1:111111111111:key/1",
    )
    f2 = Finding(
        rule_id="PQL-ALB-001",
        rule_title="ALB",
        resource=Resource(
            type="aws_lb_listener",
            name="alb1",
            attributes={"arn": "arn:aws:elasticloadbalancing:us-east-1:222222222222:listener/1"},
            origin=Origin.IAC,
        ),
        severity=Severity.CRITICAL,
        exposure=ExposureType.CONFIDENTIALITY,
        message="Listener in arn:aws:elasticloadbalancing:us-east-1:222222222222:listener/1",
    )
    f3 = Finding(
        rule_id="PQL-ACM-001",
        rule_title="ACM",
        resource=Resource(
            type="aws_acm_certificate",
            name="cert1",
            attributes={"arn": "arn:aws:acm:us-east-1:111111111111:cert/1"},
            origin=Origin.IAC,
        ),
        severity=Severity.HIGH,
        exposure=ExposureType.AUTHENTICITY,
        message="Cert in arn:aws:acm:us-east-1:111111111111:cert/1",
    )

    redacted = redact_findings([f1, f2, f3], enabled=True)

    # 111111111111 < 222222222222 alphanumerically
    assert "ACCT-1" in redacted[0].message
    assert "111111111111" not in redacted[0].message

    assert "ACCT-2" in redacted[1].message
    assert "222222222222" not in redacted[1].message

    assert "ACCT-1" in redacted[2].message
    assert "111111111111" not in redacted[2].message


def test_redact_nested_attributes_and_lists():
    finding = Finding(
        rule_id="PQL-S3-001",
        rule_title="S3",
        resource=Resource(
            type="aws_s3_bucket",
            name="nested-bucket",
            attributes={
                "rules": [
                    {
                        "destination": {
                            "arn": "arn:aws:s3:us-east-1:123456789012:accesspoint/my-ap",
                            "account_id": "123456789012",
                        }
                    }
                ],
                "principals": [
                    "arn:aws:iam::123456789012:root",
                    "arn:aws:iam::999999999999:role/CrossAccount",
                ],
            },
            origin=Origin.IAC,
        ),
        severity=Severity.INFO,
        exposure=ExposureType.CONFIDENTIALITY,
        message="Bucket uses nested rules",
    )

    redacted = redact_findings([finding], enabled=True)
    attrs = redacted[0].resource.attributes

    assert (
        attrs["rules"][0]["destination"]["arn"] == "arn:aws:s3:us-east-1:ACCT-1:accesspoint/my-ap"
    )
    assert attrs["rules"][0]["destination"]["account_id"] == "ACCT-1"
    assert attrs["principals"][0] == "arn:aws:iam::ACCT-1:root"
    assert attrs["principals"][1] == "arn:aws:iam::ACCT-2:role/CrossAccount"


def test_disabled_redaction_returns_unredacted_deepcopy():
    original_arn = "arn:aws:kms:us-east-1:123456789012:key/123"
    finding = Finding(
        rule_id="PQL-KMS-001",
        rule_title="KMS",
        resource=Resource(
            type="aws_kms_key",
            name="key1",
            attributes={"arn": original_arn},
            origin=Origin.IAC,
        ),
        severity=Severity.HIGH,
        exposure=ExposureType.AUTHENTICITY,
        message=f"Key {original_arn}",
    )

    result = redact_findings([finding], enabled=False)

    assert result[0].message == f"Key {original_arn}"
    assert result[0].resource.attributes["arn"] == original_arn

    # Verify deep copy (modifying result doesn't affect original)
    result[0].message = "mutated"
    assert finding.message != "mutated"


def test_no_leak_of_mapping_in_output():
    finding = Finding(
        rule_id="PQL-KMS-001",
        rule_title="KMS",
        resource=Resource(
            type="aws_kms_key",
            name="k1",
            attributes={"arn": "arn:aws:kms:us-east-1:123456789012:key/1"},
            origin=Origin.IAC,
        ),
        severity=Severity.HIGH,
        exposure=ExposureType.AUTHENTICITY,
        message="KMS key",
    )

    redacted = redact_findings([finding])
    redacted_finding = redacted[0]

    # Ensure no extra mapping attribute is added to the Finding or Resource models
    assert not hasattr(redacted_finding, "account_map")
    assert not hasattr(redacted_finding.resource, "account_map")
    assert "account_map" not in redacted_finding.model_dump()
