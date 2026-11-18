from pqlint.config import DEFAULT_CONFIG, Config
from pqlint.engine.scoring import evaluate_mosca_risk, score_findings
from pqlint.model import ExposureType, Finding, Origin, Resource, Severity


def test_config_defaults():
    config = Config()
    assert config.shelf_life_years == 10
    assert config.migration_years == 3
    assert config.crqc_years == 12
    assert config.X == 10
    assert config.Y == 3
    assert config.Z == 12


def test_confidentiality_risk_condition_met():
    # X (10) + Y (3) = 13 > Z (12)
    resource = Resource(
        type="aws_lb_listener",
        name="alb_listener",
        attributes={"ssl_policy": "ELBSecurityPolicy-2016-08"},
        origin=Origin.IAC,
    )
    finding = Finding(
        rule_id="PQL-ALB-001",
        rule_title="ALB Listener lacks post-quantum hybrid TLS policy",
        resource=resource,
        severity=Severity.CRITICAL,
        exposure=ExposureType.CONFIDENTIALITY,
        message="Listener uses vulnerable TLS policy.",
    )

    scored = evaluate_mosca_risk(
        finding, Config(shelf_life_years=10, migration_years=3, crqc_years=12)
    )

    # Keeps base severity CRITICAL
    assert scored.severity == Severity.CRITICAL
    assert (
        "Mosca score: X (10) + Y (3) > Z (12). Z is an assumption, not a prediction."
        in scored.message
    )

    # Ensure original finding is not mutated
    assert finding.message == "Listener uses vulnerable TLS policy."
    assert finding.severity == Severity.CRITICAL


def test_confidentiality_risk_condition_not_met():
    # X (5) + Y (2) = 7 <= Z (50)
    resource = Resource(
        type="aws_s3_bucket",
        name="s3_bucket",
        attributes={},
        origin=Origin.IAC,
    )
    finding = Finding(
        rule_id="PQL-S3-001",
        rule_title="S3 Bucket Encryption",
        resource=resource,
        severity=Severity.HIGH,
        exposure=ExposureType.CONFIDENTIALITY,
        message="S3 Bucket uses standard encryption.",
    )

    scored = evaluate_mosca_risk(
        finding, Config(shelf_life_years=5, migration_years=2, crqc_years=50)
    )

    # Downgrades to INFO
    assert scored.severity == Severity.INFO
    assert (
        "Mosca score: X (5) + Y (2) <= Z (50). Z is an assumption, not a prediction."
        in scored.message
    )


def test_authenticity_risk_condition_met():
    # Y (5) > Z (2) -> Condition met
    resource = Resource(
        type="aws_kms_key",
        name="asym_key",
        attributes={"customer_master_key_spec": "RSA_2048"},
        origin=Origin.IAC,
    )
    finding = Finding(
        rule_id="PQL-KMS-001",
        rule_title="Asymmetric KMS Key",
        resource=resource,
        severity=Severity.HIGH,
        exposure=ExposureType.AUTHENTICITY,
        message="KMS key uses RSA_2048.",
    )

    scored = evaluate_mosca_risk(
        finding, Config(shelf_life_years=20, migration_years=5, crqc_years=2)
    )

    # Shelf life X (20) ignored; Y (5) > Z (2) -> Severity maintained
    assert scored.severity == Severity.HIGH
    assert "Mosca score: Y (5) > Z (2). Z is an assumption, not a prediction." in scored.message


def test_authenticity_risk_condition_not_met_default_config():
    # Default: Y (3) <= Z (12) -> Condition NOT met
    resource = Resource(
        type="aws_acm_certificate",
        name="cert",
        attributes={"key_algorithm": "RSA_2048"},
        origin=Origin.IAC,
    )
    finding = Finding(
        rule_id="PQL-ACM-001",
        rule_title="ACM Certificate",
        resource=resource,
        severity=Severity.HIGH,
        exposure=ExposureType.AUTHENTICITY,
        message="Certificate uses RSA_2048.",
    )

    scored = evaluate_mosca_risk(finding, DEFAULT_CONFIG)

    # Downgrades to INFO
    assert scored.severity == Severity.INFO
    assert "Mosca score: Y (3) <= Z (12). Z is an assumption, not a prediction." in scored.message


def test_score_findings_batch():
    f1 = Finding(
        rule_id="PQL-ALB-001",
        rule_title="ALB",
        resource=Resource(type="aws_lb_listener", name="alb", origin=Origin.IAC),
        severity=Severity.CRITICAL,
        exposure=ExposureType.CONFIDENTIALITY,
        message="ALB finding.",
    )
    f2 = Finding(
        rule_id="PQL-KMS-001",
        rule_title="KMS",
        resource=Resource(type="aws_kms_key", name="kms", origin=Origin.IAC),
        severity=Severity.HIGH,
        exposure=ExposureType.AUTHENTICITY,
        message="KMS finding.",
    )

    # Using dictionary as config
    config_dict = {"shelf_life_years": 10, "migration_years": 3, "crqc_years": 12}
    scored = score_findings([f1, f2], config=config_dict)

    assert len(scored) == 2
    # f1: X(10) + Y(3) = 13 > 12 -> CRITICAL maintained
    assert scored[0].severity == Severity.CRITICAL
    assert "X (10) + Y (3) > Z (12)" in scored[0].message

    # f2: Y(3) <= 12 -> Downgraded to INFO
    assert scored[1].severity == Severity.INFO
    assert "Y (3) <= Z (12)" in scored[1].message


def test_structured_mosca_score_confidentiality():
    resource = Resource(
        type="aws_lb_listener",
        name="alb_listener",
        origin=Origin.IAC,
    )
    finding = Finding(
        rule_id="PQL-ALB-001",
        rule_title="ALB Listener TLS",
        resource=resource,
        severity=Severity.CRITICAL,
        exposure=ExposureType.CONFIDENTIALITY,
        message="Vulnerable TLS policy.",
    )
    scored = evaluate_mosca_risk(
        finding, Config(shelf_life_years=10, migration_years=3, crqc_years=12)
    )
    assert scored.mosca is not None
    assert scored.mosca.x == 10
    assert scored.mosca.y == 3
    assert scored.mosca.z == 12
    assert scored.mosca.at_risk is True


def test_structured_mosca_score_authenticity():
    # Audit Check 1: Shelf life x must be None for Authenticity
    resource = Resource(
        type="aws_kms_key",
        name="asym_key",
        origin=Origin.IAC,
    )
    finding = Finding(
        rule_id="PQL-KMS-001",
        rule_title="Asymmetric KMS Key",
        resource=resource,
        severity=Severity.HIGH,
        exposure=ExposureType.AUTHENTICITY,
        message="RSA key.",
    )
    scored = evaluate_mosca_risk(
        finding, Config(shelf_life_years=10, migration_years=3, crqc_years=12)
    )
    assert scored.mosca is not None
    assert scored.mosca.x is None
    assert scored.mosca.y == 3
    assert scored.mosca.z == 12
    assert scored.mosca.at_risk is False


def test_structured_mosca_unknown_severity():
    resource = Resource(
        type="aws_kms_key",
        name="asym_key",
        origin=Origin.IAC,
    )
    finding = Finding(
        rule_id="PQL-KMS-001",
        rule_title="Asymmetric KMS Key",
        resource=resource,
        severity=Severity.UNKNOWN,
        exposure=ExposureType.AUTHENTICITY,
        message="Unresolved attribute.",
    )
    scored = evaluate_mosca_risk(finding)
    assert scored.mosca is None
    assert scored.severity == Severity.UNKNOWN


def test_model_dump_backwards_compatibility():
    # Audit Check 2: Serialization and deserialization via model_dump()
    from pqlint.model import Location, ScanResult

    res = Resource(
        type="aws_lb_listener",
        name="test_alb",
        location=Location(file_path="modules/alb/main.tf", start_line=42),
        fingerprint="pql-fingerprint-12345",
        origin=Origin.IAC,
    )
    assert res.source_location == "modules/alb/main.tf:42"

    finding = Finding(
        rule_id="PQL-ALB-001",
        rule_title="ALB TLS",
        resource=res,
        severity=Severity.CRITICAL,
        exposure=ExposureType.CONFIDENTIALITY,
        message="Test message",
    )
    scored = evaluate_mosca_risk(finding)
    scan_result = ScanResult(resources=[res], findings=[scored])

    dumped = scan_result.model_dump()
    assert dumped["resources"][0]["location"]["file_path"] == "modules/alb/main.tf"
    assert dumped["resources"][0]["location"]["start_line"] == 42
    assert dumped["resources"][0]["fingerprint"] == "pql-fingerprint-12345"
    assert dumped["findings"][0]["mosca"]["x"] == 10
    assert dumped["findings"][0]["mosca"]["y"] == 3
    assert dumped["findings"][0]["mosca"]["z"] == 12
    assert dumped["findings"][0]["mosca"]["at_risk"] is True

    # Re-validate from dict
    restored = ScanResult.model_validate(dumped)
    assert restored.resources[0].location is not None
    assert restored.resources[0].location.file_path == "modules/alb/main.tf"
    assert restored.resources[0].location.start_line == 42
    assert restored.resources[0].source_location == "modules/alb/main.tf:42"
    assert restored.findings[0].mosca is not None
    assert restored.findings[0].mosca.at_risk is True
