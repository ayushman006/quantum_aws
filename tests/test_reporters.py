"""Unit and integration tests for multi-format export layer (Milestone 2).

Tests:
- export_json (valid JSON serialization with 2-space indentation)
- export_markdown (human-readable table of findings)
- export_sarif (SARIF 2.1.0 schema compliance and location mapping)
- export_cbom (CycloneDX 1.6 CBOM schema compliance with cryptographic-asset types)
- CLI integration with --format and -o / --output options
- Zero leak redaction through all output formats
"""

import json
from pathlib import Path

from typer.testing import CliRunner

from pqlint.cli import app
from pqlint.model import (
    ExposureType,
    Finding,
    Location,
    MoscaScore,
    Origin,
    Resource,
    ScanResult,
    Severity,
)
from pqlint.reporters.exports import (
    export_cbom,
    export_json,
    export_markdown,
    export_sarif,
)

runner = CliRunner()


def _sample_scan_result() -> ScanResult:
    res = Resource(
        type="aws_kms_key",
        name="test_key",
        origin=Origin.IAC,
        location=Location(file_path="infra/main.tf", start_line=15),
        attributes={"customer_master_key_spec": "RSA_2048"},
    )
    finding = Finding(
        rule_id="PQL-KMS-001",
        rule_title="Quantum-Vulnerable KMS Key",
        resource=res,
        severity=Severity.HIGH,
        exposure=ExposureType.CONFIDENTIALITY,
        message="RSA-2048 key is vulnerable to Shor's algorithm.",
        mosca=MoscaScore(x=10, y=3, z=12, at_risk=True),
    )
    return ScanResult(resources=[res], findings=[finding])


def test_export_json(tmp_path: Path):
    scan_result = _sample_scan_result()
    out_file = tmp_path / "report.json"
    export_json(scan_result, out_file)

    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(data["resources"]) == 1
    assert data["resources"][0]["name"] == "test_key"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["rule_id"] == "PQL-KMS-001"
    assert data["findings"][0]["mosca"]["at_risk"] is True


def test_export_markdown(tmp_path: Path):
    scan_result = _sample_scan_result()
    out_file = tmp_path / "report.md"
    export_markdown(scan_result, out_file)

    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "# Post-Quantum Readiness Findings" in content
    assert "| HIGH | PQL-KMS-001 | aws_kms_key.test_key | confidentiality |" in content


def test_export_sarif_schema_and_locations(tmp_path: Path):
    scan_result = _sample_scan_result()
    out_file = tmp_path / "report.sarif"
    export_sarif(scan_result, out_file)

    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"

    # Audit Check 1: SARIF driver name
    assert len(data["runs"]) == 1
    assert data["runs"][0]["tool"]["driver"]["name"] == "pqlint"

    results = data["runs"][0]["results"]
    assert len(results) == 1
    r = results[0]
    assert r["ruleId"] == "PQL-KMS-001"
    assert r["level"] == "error"
    assert r["message"]["text"] == "RSA-2048 key is vulnerable to Shor's algorithm."

    phys_loc = r["locations"][0]["physicalLocation"]
    assert phys_loc["artifactLocation"]["uri"] == "infra/main.tf"
    assert phys_loc["region"]["startLine"] == 15


def test_export_sarif_omits_region_when_start_line_is_none(tmp_path: Path):
    res = Resource(
        type="aws_kms_key",
        name="no_line_key",
        origin=Origin.IAC,
        location=Location(file_path="infra/kms.tf", start_line=None),
    )
    finding = Finding(
        rule_id="PQL-KMS-001",
        rule_title="Quantum-Vulnerable KMS Key",
        resource=res,
        severity=Severity.HIGH,
        exposure=ExposureType.CONFIDENTIALITY,
        message="RSA key found",
    )
    scan_result = ScanResult(resources=[res], findings=[finding])
    out_file = tmp_path / "report.sarif"
    export_sarif(scan_result, out_file)

    data = json.loads(out_file.read_text(encoding="utf-8"))
    phys_loc = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert phys_loc["artifactLocation"]["uri"] == "infra/kms.tf"
    assert "region" not in phys_loc


def test_export_cbom_schema_and_component_types(tmp_path: Path):
    scan_result = _sample_scan_result()
    out_file = tmp_path / "report.cbom.json"
    export_cbom(scan_result, out_file)

    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.6"

    # Audit Check 2: CBOM component type
    components = data["components"]
    assert len(components) == 1
    comp = components[0]
    assert comp["type"] == "cryptographic-asset"
    assert comp["name"] == "aws_kms_key.test_key"
    assert comp["bom-ref"].startswith("pql-")


def test_cli_export_formats_and_defaults(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    tf_dir = tmp_path / "infra"
    tf_dir.mkdir()
    (tf_dir / "main.tf").write_text(
        """
        resource "aws_kms_key" "vuln_key" {
          customer_master_key_spec = "RSA_2048"
        }
        """,
        encoding="utf-8",
    )

    # 1. JSON default output: pqlint_report.json
    res_json = runner.invoke(
        app, ["scan-iac", str(tf_dir), "--format", "json", "--fail-on", "info"]
    )
    assert res_json.exit_code == 1  # Finding meets --fail-on info threshold
    assert Path("pqlint_report.json").exists()
    json_data = json.loads(Path("pqlint_report.json").read_text(encoding="utf-8"))
    assert len(json_data["findings"]) == 1

    # 2. Markdown default output: pqlint_report.md
    res_md = runner.invoke(
        app, ["scan-iac", str(tf_dir), "--format", "markdown", "--fail-on", "info"]
    )
    assert res_md.exit_code == 1
    assert Path("pqlint_report.md").exists()
    assert "# Post-Quantum Readiness Findings" in Path("pqlint_report.md").read_text(
        encoding="utf-8"
    )

    # 3. SARIF default output: pqlint_report.sarif
    res_sarif = runner.invoke(
        app, ["scan-iac", str(tf_dir), "--format", "sarif", "--fail-on", "info"]
    )
    assert res_sarif.exit_code == 1
    assert Path("pqlint_report.sarif").exists()
    sarif_data = json.loads(Path("pqlint_report.sarif").read_text(encoding="utf-8"))
    assert sarif_data["runs"][0]["tool"]["driver"]["name"] == "pqlint"

    # 4. CBOM default output: pqlint_report.cbom.json
    res_cbom = runner.invoke(
        app, ["scan-iac", str(tf_dir), "--format", "cbom", "--fail-on", "info"]
    )
    assert res_cbom.exit_code == 1
    assert Path("pqlint_report.cbom.json").exists()
    cbom_data = json.loads(Path("pqlint_report.cbom.json").read_text(encoding="utf-8"))
    assert cbom_data["components"][0]["type"] == "cryptographic-asset"

    # 5. Custom output path flag (-o / --output)
    custom_out = tmp_path / "custom" / "audit.sarif"
    res_custom = runner.invoke(
        app,
        ["scan-iac", str(tf_dir), "--format", "sarif", "-o", str(custom_out), "--fail-on", "info"],
    )
    assert res_custom.exit_code == 1
    assert custom_out.exists()


def test_cli_invalid_format_exits_with_code_2(tmp_path: Path):
    tf_dir = tmp_path / "infra"
    tf_dir.mkdir()
    (tf_dir / "main.tf").write_text('resource "aws_kms_key" "k" {}', encoding="utf-8")

    res = runner.invoke(app, ["scan-iac", str(tf_dir), "--format", "xml"])
    assert res.exit_code == 2
    assert "Invalid format 'xml'" in res.output


def test_export_redaction_guarantee(tmp_path: Path, monkeypatch):
    """Ensure raw 12-digit AWS account IDs never leak into any exported reporter file."""
    monkeypatch.chdir(tmp_path)
    tf_dir = tmp_path / "infra"
    tf_dir.mkdir()
    (tf_dir / "main.tf").write_text(
        """
        resource "aws_kms_key" "account_key" {
          arn = "arn:aws:kms:us-east-1:123456789012:key/test-id"
          customer_master_key_spec = "RSA_2048"
        }
        """,
        encoding="utf-8",
    )

    for fmt in ("json", "sarif", "cbom", "markdown"):
        res = runner.invoke(app, ["scan-iac", str(tf_dir), "--format", fmt])
        assert res.exit_code in (0, 1)

    for report_file in (
        Path("pqlint_report.json"),
        Path("pqlint_report.sarif"),
        Path("pqlint_report.cbom.json"),
        Path("pqlint_report.md"),
    ):
        assert report_file.exists()
        content = report_file.read_text(encoding="utf-8")
        assert "123456789012" not in content, (
            f"Account ID leaked into exported file {report_file.name}"
        )
