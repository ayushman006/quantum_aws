"""Multi-format export layer for pqlint findings, CBOM, and SARIF (Milestone 2).

Provides dense, standalone exporter functions using standard library json:
- export_json: Serializes the ScanResult via model_dump_json(indent=2).
- export_markdown: Generates a human-readable Markdown summary report with tables.
- export_sarif: Maps findings to a valid SARIF 2.1.0 JSON dictionary.
- export_cbom: Maps resources to a CycloneDX 1.6 JSON dictionary.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Union

from pqlint.ids import generate_deterministic_id
from pqlint.model import ScanResult

SARIF_SEVERITY_LEVEL: Dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "unknown": "warning",
}


def export_json(result: ScanResult, target_path: Union[str, Path]) -> None:
    """Serialize the ScanResult via model_dump_json(indent=2)."""
    p = Path(target_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")


def export_markdown(result: ScanResult, target_path: Union[str, Path]) -> None:
    """Generate a clean, human-readable Markdown report with a summary table of findings."""
    p = Path(target_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    lines: List[str] = [
        "# Post-Quantum Readiness Findings",
        "",
        f"**Tool Version:** {result.tool_version}  ",
        f"**Resources Scanned:** {len(result.resources)}  ",
        f"**Total Findings:** {len(result.findings)}",
        "",
    ]
    if result.findings:
        lines.extend(
            [
                "| Severity | Rule ID | Resource | Exposure | Message |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for f in result.findings:
            sev = (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).upper()
            res_name = f"{f.resource.type}.{f.resource.name}"
            exp = (f.exposure.value if hasattr(f.exposure, "value") else str(f.exposure)).lower()
            msg = f.message.replace("\n", " ").replace("|", "\\|")
            lines.append(f"| {sev} | {f.rule_id} | {res_name} | {exp} | {msg} |")
        lines.append("")
    else:
        lines.extend(["No quantum vulnerabilities found.", ""])

    if result.warnings:
        lines.append("## Warnings")
        for w in result.warnings:
            lines.append(f"- {w}")
        lines.append("")

    lines.append("*Note: Z (years to CRQC) is an assumption, not a prediction.*")
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")


def export_sarif(result: ScanResult, target_path: Union[str, Path]) -> None:
    """Map the ScanResult.findings to a valid SARIF 2.1.0 JSON dictionary."""
    results_list: List[Dict[str, Any]] = []
    rules: List[Dict[str, Any]] = []
    seen_rules: set[str] = set()

    for f in result.findings:
        if f.rule_id not in seen_rules:
            seen_rules.add(f.rule_id)
            rules.append(
                {
                    "id": f.rule_id,
                    "shortDescription": {"text": f.rule_title or f.rule_id},
                }
            )

        sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        res_entry: Dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": SARIF_SEVERITY_LEVEL.get(sev_str.lower(), "warning"),
            "message": {"text": f.message},
        }

        if f.resource.location:
            phys_loc: Dict[str, Any] = {
                "artifactLocation": {"uri": f.resource.location.file_path.replace("\\", "/")}
            }
            if f.resource.location.start_line is not None:
                phys_loc["region"] = {"startLine": f.resource.location.start_line}
            res_entry["locations"] = [{"physicalLocation": phys_loc}]

        results_list.append(res_entry)

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pqlint",
                        "version": result.tool_version,
                        "rules": rules,
                    }
                },
                "results": results_list,
            }
        ],
    }
    p = Path(target_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(sarif_doc, indent=2) + "\n", encoding="utf-8")


def export_cbom(result: ScanResult, target_path: Union[str, Path]) -> None:
    """Map the ScanResult.resources to a CycloneDX 1.6 JSON dictionary."""
    components: List[Dict[str, Any]] = []
    for r in result.resources:
        bom_ref = r.fingerprint or generate_deterministic_id(f"{r.type}::{r.name}")
        comp: Dict[str, Any] = {
            "type": "cryptographic-asset",
            "bom-ref": bom_ref,
            "name": f"{r.type}.{r.name}",
        }
        components.append(comp)

    cbom_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "pqlint",
                        "version": result.tool_version,
                    }
                ]
            }
        },
        "components": components,
    }
    p = Path(target_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cbom_doc, indent=2) + "\n", encoding="utf-8")
