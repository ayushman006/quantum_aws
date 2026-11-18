import copy
import random
import traceback
import uuid

import pytest

from pqlint.errors import RedactionLeakError
from pqlint.ids import DIGIT_12_RUN_PATTERN, generate_deterministic_id, generate_safe_id
from pqlint.model import ExposureType, Finding, Origin, Resource, ScanResult, Severity
from pqlint.redaction import Redactor, redact_scan_result


def test_r1_standalone_pattern_fails_next_to_word_chars():
    """R1: Bare IDs next to word characters (snake_case) must be discovered and redacted."""
    test_cases = [
        "account_123456789012",
        "123456789012_prod",
        "key_123456789012_x",
    ]
    for s in test_cases:
        r = Resource(type="aws_kms_key", name=s, attributes={"val": s}, origin=Origin.IAC)
        sr = ScanResult(resources=[r])
        redacted = redact_scan_result(sr)
        json_output = redacted.model_dump_json()
        assert "123456789012" not in json_output, f"Failed for input: {s}"
        assert "ACCT-1" in json_output, f"Missing placeholder for: {s}"


def test_r2_url_encoded_arns_evade_discovery():
    """R2: URL-encoded ARNs must be discovered and redacted."""
    url_arn = "arn%3Aaws%3Akms%3Aus-east-1%3A123456789012%3Akey"
    r = Resource(type="aws_kms_key", name="k", attributes={"url_arn": url_arn}, origin=Origin.IAC)
    sr = ScanResult(resources=[r])
    redacted = redact_scan_result(sr)
    json_output = redacted.model_dump_json()
    assert "123456789012" not in json_output
    assert "ACCT-1" in json_output


def test_r3_integer_dict_keys_in_nested_attributes():
    """R3: Integer dict keys in nested attributes must be redacted to string placeholders."""
    r = Resource(
        type="aws_kms_key",
        name="k",
        attributes={"mapping": {123456789012: "dev"}},
        origin=Origin.IAC,
    )
    sr = ScanResult(resources=[r])
    redacted = redact_scan_result(sr)
    json_output = redacted.model_dump_json()
    assert "123456789012" not in json_output
    assert "ACCT-1" in json_output
    # Redacted int keys must become string placeholder in dictionary
    assert "ACCT-1" in redacted.resources[0].attributes["mapping"]


def test_r4_finding_rule_title_remediation_ref_references():
    """R4: Finding fields (rule_title, remediation_ref, references) must be scanned and redacted."""
    r = Resource(type="aws_kms_key", name="k", attributes={}, origin=Origin.IAC)
    f = Finding(
        rule_id="PQL-KMS-001",
        rule_title="Vulnerability in 123456789012",
        resource=r,
        severity=Severity.HIGH,
        exposure=ExposureType.AUTHENTICITY,
        message="Vulnerable key",
        remediation_ref="ref-123456789012",
        references=["https://docs.aws.amazon.com/kms/123456789012/guide"],
    )
    sr = ScanResult(findings=[f])
    redacted = redact_scan_result(sr)
    json_output = redacted.model_dump_json()
    assert "123456789012" not in json_output
    assert "ACCT-1" in redacted.findings[0].rule_title
    assert "ACCT-1" in str(redacted.findings[0].remediation_ref)
    assert "ACCT-1" in redacted.findings[0].references[0]


def test_r5_timestamp_exemptions_removed():
    """R5: Timestamp heuristic must not exempt IDs under keys with date/update/created or shape 202611142045."""
    test_keys = [
        ("validated_account_id", "123456789012"),
        ("update_account", "123456789012"),
        ("created_by_account", "123456789012"),
        ("candidate_account", "202611142045"),  # Date-shape heuristic 12-digit number
        ("candidate_account_int", 202611142045),  # Int form
    ]
    for key_name, acct_val in test_keys:
        r = Resource(
            type="aws_kms_key", name="k", attributes={key_name: acct_val}, origin=Origin.IAC
        )
        sr = ScanResult(resources=[r])
        redacted = redact_scan_result(sr)
        json_output = redacted.model_dump_json()
        assert str(acct_val) not in json_output, f"Leaked {acct_val} under key {key_name}"


def test_r6_leak_guard_is_independent_and_runs_always():
    """R6: Leak guard must not be tautological and must run even when discovery found nothing."""
    redactor = Redactor()
    with pytest.raises(RedactionLeakError):
        redactor.verify('{"unmasked": "123456789012"}')

    with pytest.raises(RedactionLeakError):
        redactor.verify('{"unmasked_arn": "arn:aws:kms:us-east-1:123456789012:key/test"}')


def test_r7_guard_exception_message_never_contains_raw_id():
    """R7: RedactionLeakError must never contain raw account IDs, ARNs, or surrounding context."""
    raw_id = "123456789012"
    redactor = Redactor()
    try:
        redactor.verify(f'{{"key": "{raw_id}"}}')
        pytest.fail("Redactor.verify should have raised RedactionLeakError")
    except RedactionLeakError as e:
        err_str = str(e)
        err_repr = repr(e)
        tb_str = "".join(traceback.format_exception(type(e), e, e.__traceback__))
        assert raw_id not in err_str, "Raw ID found in str(e)"
        assert raw_id not in err_repr, "Raw ID found in repr(e)"
        assert raw_id not in tb_str, "Raw ID found in traceback"


def test_r8_guard_runs_on_final_rendered_output():
    """R8: Redactor.verify() must verify rendered text (JSON, SARIF, CBOM, Markdown, table)."""
    redactor = Redactor()
    # Clean text passes
    redactor.verify("Clean table: Resource aws_kms_key in account ACCT-1 is vulnerable.")

    # Unmasked text fails
    with pytest.raises(RedactionLeakError):
        redactor.verify(
            "Rendered table: Resource aws_kms_key in account 123456789012 is vulnerable."
        )


def test_r9_leading_zero_ids_written_as_unquoted_ints():
    """R9: In KNOWN_ACCOUNT_ID_KEYS, ints >= 10**9 are zero-padded to 12 digits and registered."""
    r = Resource(
        type="aws_kms_key", name="k", attributes={"account_id": 12345678901}, origin=Origin.IAC
    )
    sr = ScanResult(resources=[r])
    redacted = redact_scan_result(sr)
    json_output = redacted.model_dump_json()
    assert "12345678901" not in json_output
    assert "012345678901" not in json_output
    assert "ACCT-1" in json_output


def test_terraform_arn_styles_and_partitions():
    """Test various Terraform-style ARNs: interpolated region, partition, GovCloud, uppercase."""
    test_arns = [
        ("arn:aws:kms:${var.region}:123456789012:key/x", "arn:aws:kms:${var.region}:ACCT-1:key/x"),
        (
            "arn:${var.partition}:s3:us-east-1:123456789012:bucket",
            "arn:${var.partition}:s3:us-east-1:ACCT-1:bucket",
        ),
        ("arn:aws:iam::123456789012:root", "arn:aws:iam::ACCT-1:root"),
        ("arn:aws:iam::123456789012:", "arn:aws:iam::ACCT-1:"),
        ("arn:aws:iam::123456789012", "arn:aws:iam::ACCT-1"),
        (
            "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/x",
            "arn:aws-us-gov:kms:us-gov-west-1:ACCT-1:key/x",
        ),
        ("ARN:AWS:KMS:US-EAST-1:123456789012:KEY/X", "ARN:AWS:KMS:US-EAST-1:ACCT-1:KEY/X"),
    ]
    for raw_arn, expected in test_arns:
        r = Resource(type="aws_kms_key", name="k", attributes={"arn": raw_arn}, origin=Origin.IAC)
        sr = ScanResult(resources=[r])
        redacted = redact_scan_result(sr)
        json_output = redacted.model_dump_json()
        assert "123456789012" not in json_output, f"Failed for {raw_arn}"
        assert expected in redacted.resources[0].attributes["arn"]


def test_value_shapes_identifiers_and_policies():
    """Test policy JSON, condition blocks, arrays, file paths, and warnings."""
    r = Resource(
        type="aws_kms_key",
        name="key-in-path",
        source_location="accounts/123456789012/main.tf:42",
        attributes={
            "account_id_int": 123456789012,
            "identifiers": ["123456789012"],
            "policy_json": '{"Statement":[{"Principal":{"AWS":"123456789012"}}]}',
            "conditions": {"StringEquals": {"aws:SourceAccount": "123456789012"}},
            "bare_number_in_unrelated_key": "123456789012",
        },
        origin=Origin.IAC,
    )
    sr = ScanResult(
        resources=[r],
        warnings=["Parser warning for account 123456789012 in region us-east-1"],
    )
    redacted = redact_scan_result(sr)
    json_output = redacted.model_dump_json()

    assert "123456789012" not in json_output
    assert "accounts/ACCT-1/main.tf:42" == redacted.resources[0].source_location
    assert redacted.resources[0].attributes["account_id_int"] == "ACCT-1"
    assert redacted.resources[0].attributes["identifiers"] == ["ACCT-1"]
    assert "ACCT-1" in redacted.resources[0].attributes["policy_json"]
    assert (
        redacted.resources[0].attributes["conditions"]["StringEquals"]["aws:SourceAccount"]
        == "ACCT-1"
    )
    assert "ACCT-1" in redacted.warnings[0]


def test_non_corruption_of_small_ints_and_unrelated_numbers():
    """Verify small ints, ports, counts, and 11-digit/13-digit numbers remain byte-identical."""
    original_attrs = {
        "count": 0,
        "n": 1,
        "port": 443,
        "mapping": {0: "a", 1: "b"},
        "epoch_ms": 1700000000000,  # 13 digits: must not be corrupted
        "non_account_11_digits": 12345678901,  # 11 digits under non-account key: not corrupted
    }
    r = Resource(
        type="aws_kms_key",
        name="clean_key",
        attributes=copy.deepcopy(original_attrs),
        origin=Origin.IAC,
    )
    sr = ScanResult(resources=[r])
    redacted = redact_scan_result(sr)

    # Output attributes must remain completely identical
    assert redacted.resources[0].attributes == original_attrs


def test_determinism_across_shuffled_inputs():
    """Shuffling resources and findings must yield identical deterministic ACCT-N mappings."""
    # Order A: 987654321098 first, then 123456789012, then 555555555555
    r_a1 = Resource(
        type="t", name="res_1", attributes={"account_id": "987654321098"}, origin=Origin.IAC
    )
    r_a2 = Resource(
        type="t", name="res_2", attributes={"account_id": "123456789012"}, origin=Origin.IAC
    )
    r_a3 = Resource(
        type="t", name="res_3", attributes={"account_id": "555555555555"}, origin=Origin.IAC
    )
    red_a = redact_scan_result(ScanResult(resources=[r_a1, r_a2, r_a3]))

    # Order B: 123456789012 first, then 555555555555, then 987654321098
    r_b1 = Resource(
        type="t", name="res_2", attributes={"account_id": "123456789012"}, origin=Origin.IAC
    )
    r_b2 = Resource(
        type="t", name="res_3", attributes={"account_id": "555555555555"}, origin=Origin.IAC
    )
    r_b3 = Resource(
        type="t", name="res_1", attributes={"account_id": "987654321098"}, origin=Origin.IAC
    )
    red_b = redact_scan_result(ScanResult(resources=[r_b1, r_b2, r_b3]))

    # In both runs, 123456789012 -> ACCT-1, 555555555555 -> ACCT-2, 987654321098 -> ACCT-3
    map_a = {r.name: r.attributes["account_id"] for r in red_a.resources}
    map_b = {r.name: r.attributes["account_id"] for r in red_b.resources}

    assert map_a["res_2"] == "ACCT-1"  # 123456789012
    assert map_a["res_3"] == "ACCT-2"  # 555555555555
    assert map_a["res_1"] == "ACCT-3"  # 987654321098

    assert map_b["res_2"] == "ACCT-1"
    assert map_b["res_3"] == "ACCT-2"
    assert map_b["res_1"] == "ACCT-3"


def test_immutability_input_unchanged():
    """The original ScanResult object and nested attributes must remain completely unmutated."""
    orig_attrs = {
        "account_id": 123456789012,
        "nested": {"arn": "arn:aws:kms:us-east-1:123456789012:key/test"},
        "list": [123456789012],
    }
    r = Resource(
        type="aws_kms_key", name="k", attributes=copy.deepcopy(orig_attrs), origin=Origin.IAC
    )
    f = Finding(
        rule_id="PQL-KMS-001",
        rule_title="Title 123456789012",
        resource=r,
        severity=Severity.HIGH,
        exposure=ExposureType.AUTHENTICITY,
        message="Message 123456789012",
    )
    sr = ScanResult(resources=[r], findings=[f])

    sr_copy_before = sr.model_copy(deep=True)
    _ = redact_scan_result(sr)

    # Ensure deep equality between input before and after redaction
    assert sr.model_dump() == sr_copy_before.model_dump()


def test_generated_id_property_over_10000_values():
    """Item 10: Property test over 10,000 generated values asserting no run of 12 digits exists."""
    # Test 5,000 random safe IDs
    for _ in range(5000):
        val = generate_safe_id(prefix="pql")
        assert not DIGIT_12_RUN_PATTERN.search(val), f"12-digit run in generated ID: {val}"

    # Test 5,000 deterministic safe IDs
    for i in range(5000):
        val = generate_deterministic_id(seed_text=f"test-seed-{i}", prefix="pql")
        assert not DIGIT_12_RUN_PATTERN.search(val), f"12-digit run in deterministic ID: {val}"


def test_invariant_uuid_hex_and_ec2_ids_never_raise():
    """Item 9 Invariant: For random UUIDs, hex strings, EC2-style IDs, redact_scan_result never raises."""
    test_attrs = {
        "random_uuids": [str(uuid.uuid4()) for _ in range(20)],
        "ec2_ids": [f"i-{random.getrandbits(64):016x}" for _ in range(20)],
        "hex_tokens": [f"{random.getrandbits(128):032x}" for _ in range(20)],
        "kms_key_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    }
    r = Resource(type="aws_kms_key", name="random_key", attributes=test_attrs, origin=Origin.IAC)
    sr = ScanResult(resources=[r])

    # Must never raise RedactionLeakError or any other exception
    redacted = redact_scan_result(sr)
    assert redacted is not None


def test_disabled_redaction_returns_unredacted_deepcopy():
    """Item 12: --no-redact (enabled=False) returns an unmasked deep copy without running the guard."""
    original_arn = "arn:aws:kms:us-east-1:123456789012:key/test"
    r = Resource(type="aws_kms_key", name="k", attributes={"arn": original_arn}, origin=Origin.IAC)
    sr = ScanResult(resources=[r])

    redacted = redact_scan_result(sr, enabled=False)
    assert redacted.resources[0].attributes["arn"] == original_arn

    # Verify deep copy
    redacted.resources[0].attributes["arn"] = "mutated"
    assert sr.resources[0].attributes["arn"] == original_arn


def test_redactor_repr_and_dict_never_exposes_real_ids():
    """Verify Redactor repr and __dict__ never expose discovered real account IDs."""
    red = Redactor()
    raw_id = "123456789012"
    r = Resource(
        type="aws_kms_key",
        name="k",
        attributes={"arn": f"arn:aws:kms:us-east-1:{raw_id}:key/x"},
        origin=Origin.IAC,
    )
    red.redact(ScanResult(resources=[r]))

    repr_text = repr(red)
    dict_text = str(getattr(red, "__dict__", ""))
    combined = repr_text + dict_text

    assert raw_id not in repr_text, "Raw ID leaked in Redactor.__repr__"
    assert raw_id not in dict_text, "Raw ID leaked in Redactor.__dict__"
    assert raw_id not in combined, "Raw ID leaked in Redactor inspection"


def test_guard_independent_tolerant_arn_check():
    """Verify Redactor.verify() independently detects tolerant-ARN structures even without discovery."""
    red = Redactor()
    with pytest.raises(RedactionLeakError):
        red.verify("Text containing unmasked ARN arn:aws:kms:us-east-1:123456789012:key/unredacted")


def test_ids_under_specific_keys_as_str_and_int():
    """Verify IDs under update_account, created_by_account, and candidate_account as both str and int."""
    raw_id_str = "123456789012"
    raw_id_int = 123456789012
    cases = [
        ("update_account", raw_id_str),
        ("update_account", raw_id_int),
        ("created_by_account", raw_id_str),
        ("created_by_account", raw_id_int),
        ("candidate_account", raw_id_str),
        ("candidate_account", raw_id_int),
    ]
    for key_name, val in cases:
        r = Resource(type="aws_kms_key", name="k", attributes={key_name: val}, origin=Origin.IAC)
        sr = ScanResult(resources=[r])
        redacted = redact_scan_result(sr)
        json_output = redacted.model_dump_json()
        assert "123456789012" not in json_output, f"Failed for {key_name}={val}"
        assert "ACCT-1" in json_output, f"Missing placeholder for {key_name}={val}"


def test_timestamp_shape_202611142045():
    """Verify the 12-digit timestamp-like number 202611142045 is masked and not exempted."""
    ts_str = "202611142045"
    ts_int = 202611142045
    r = Resource(
        type="aws_kms_key",
        name="k",
        attributes={"timestamp": ts_str, "timestamp_int": ts_int},
        origin=Origin.IAC,
    )
    f = Finding(
        rule_id="PQL-KMS-001",
        rule_title="Finding",
        resource=r,
        severity=Severity.HIGH,
        exposure=ExposureType.AUTHENTICITY,
        message=f"Created on {ts_str}",
    )
    sr = ScanResult(resources=[r], findings=[f])
    redacted = redact_scan_result(sr)
    json_output = redacted.model_dump_json()

    assert ts_str not in json_output
    assert "ACCT-1" in json_output


def test_ids_in_warnings_and_file_paths():
    """Verify account IDs inside warnings and source file locations are redacted."""
    raw_id = "123456789012"
    r = Resource(
        type="aws_kms_key",
        name="k",
        source_location=f"accounts/{raw_id}/infra/main.tf:10",
        attributes={},
        origin=Origin.IAC,
    )
    sr = ScanResult(
        resources=[r],
        warnings=[f"Could not parse accounts/{raw_id}/infra/main.tf: syntax warning"],
    )
    redacted = redact_scan_result(sr)
    json_output = redacted.model_dump_json()

    assert raw_id not in json_output
    assert "accounts/ACCT-1/infra/main.tf:10" == redacted.resources[0].source_location
    assert "Could not parse accounts/ACCT-1/infra/main.tf: syntax warning" == redacted.warnings[0]


def test_keys_of_arn_form():
    """Verify dictionary keys formatted as ARNs have their account IDs redacted."""
    raw_id = "123456789012"
    arn_key = f"arn:aws:kms:us-east-1:{raw_id}:key/my-key"
    r = Resource(
        type="aws_kms_key", name="k", attributes={arn_key: "key_metadata"}, origin=Origin.IAC
    )
    sr = ScanResult(resources=[r])
    redacted = redact_scan_result(sr)
    json_output = redacted.model_dump_json()

    assert raw_id not in json_output
    assert "arn:aws:kms:us-east-1:ACCT-1:key/my-key" in redacted.resources[0].attributes
