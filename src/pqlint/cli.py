from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from pqlint import __version__
from pqlint.config import Config
from pqlint.engine.rules import RuleEngine
from pqlint.engine.scoring import score_findings
from pqlint.model import ScanResult
from pqlint.parsers.terraform import parse_terraform_directory
from pqlint.redaction import redact_scan_result, redact_text
from pqlint.reporters.exports import (
    export_cbom,
    export_json,
    export_markdown,
    export_sarif,
)

app = typer.Typer(help="pqlint: Open-Source Post-Quantum Readiness Linter for AWS Infrastructure")
console = Console()

DEFAULT_RULES_DIR = Path(__file__).resolve().parent / "data" / "rules"

DEFAULT_REPORT_FILES = {
    "json": "pqlint_report.json",
    "sarif": "pqlint_report.sarif",
    "cbom": "pqlint_report.cbom.json",
    "markdown": "pqlint_report.md",
}

SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
    "unknown": 3,
}


@app.command("scan-iac")
def scan_iac(
    target_dir: str = typer.Argument(..., help="Path to the directory containing .tf files"),
    format: str = typer.Option(
        "table",
        "--format",
        help="Output format (table, json, sarif, cbom, markdown)",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path (defaults to pqlint_report.<ext> for file formats)",
    ),
    no_redact: bool = typer.Option(False, "--no-redact", help="Disable AWS account ID redaction"),
    fail_on: str = typer.Option(
        "high",
        "--fail-on",
        help="Exit with code 1 only if findings meet or exceed this severity (critical, high, medium, low, info)",
    ),
    shelf_life_years: int = typer.Option(
        10, "--shelf-life", "-x", help="Data shelf life in years (X)"
    ),
    migration_years: int = typer.Option(
        3, "--migration-years", "-y", help="Migration time in years (Y)"
    ),
    crqc_years: int = typer.Option(12, "--crqc-years", "-z", help="Years until CRQC arrival (Z)"),
):
    """
    Scans a directory of Terraform files offline for quantum-vulnerable cryptography.
    """
    fmt = format.lower()
    if fmt not in ("table", "json", "sarif", "cbom", "markdown"):
        console.print(
            f"[red]Error: Invalid format '{format}'. Supported formats: table, json, sarif, cbom, markdown[/red]"
        )
        raise typer.Exit(code=2)

    # Sanitize user-supplied path before console output
    safe_target_dir = redact_text(target_dir) or target_dir
    console.print(
        f"[bold blue]Scanning local Terraform directory:[/bold blue] {escape(safe_target_dir)}"
    )

    # 1. Parse offline
    parser_warnings: list[str] = []
    resources = parse_terraform_directory(target_dir, warnings=parser_warnings)
    console.print(f"Parsed {len(resources)} resources.")
    for pw in parser_warnings:
        console.print(f"[yellow]Warning: {pw}[/yellow]")

    if not resources:
        console.print("[yellow]No supported AWS resources found in the target directory.[/yellow]")
        raise typer.Exit(code=0)

    # 2. Evaluate rules
    engine = RuleEngine(DEFAULT_RULES_DIR)
    engine.load_rules()
    findings = engine.evaluate(resources)
    unresolved_count = engine.unresolved_count

    # 3. Score findings with Mosca risk model (PRD FR-20, FR-21, FR-22)
    config = Config(
        shelf_life_years=shelf_life_years,
        migration_years=migration_years,
        crqc_years=crqc_years,
    )
    if findings:
        findings = score_findings(findings, config)

    # 4. Mandatory redaction layer between findings and reporter (PRD FR-60, FR-64)
    if no_redact:
        console.print(
            "[yellow bold]WARNING: Account ID redaction is disabled (--no-redact). Output may contain sensitive AWS account IDs.[/yellow bold]"
        )
    warnings = [
        f"Attribute '{u.get('resource', '')}' could not be resolved offline."
        for u in engine.unresolved_attributes
    ]
    warnings.extend(parser_warnings)
    if unresolved_count > 0:
        warnings.append(f"{unresolved_count} attributes could not be resolved.")

    scan_result = ScanResult(
        resources=resources,
        findings=findings,
        warnings=warnings,
        unresolved_count=unresolved_count,
    )
    scan_result = redact_scan_result(scan_result, enabled=not no_redact)
    findings = scan_result.findings

    # 5. Route to reporter
    if fmt == "table":
        if not findings:
            console.print("[green]No quantum vulnerabilities found! ✓[/green]")
            if unresolved_count > 0:
                console.print(
                    f"[yellow]{unresolved_count} attributes could not be resolved[/yellow]"
                )
            raise typer.Exit(code=0)

        table = Table(title="Post-Quantum Readiness Findings", show_lines=True)
        table.add_column("Severity")
        table.add_column("Rule ID", style="cyan")
        table.add_column("Resource", style="magenta")
        table.add_column("Exposure")
        table.add_column("Message")

        for finding in findings:
            sev_str = finding.severity.upper()
            if finding.severity == "unknown":
                sev_formatted = f"[yellow bold]{sev_str}[/yellow bold]"
            elif finding.severity in ("critical", "high"):
                sev_formatted = f"[red bold]{sev_str}[/red bold]"
            elif finding.severity == "medium":
                sev_formatted = f"[yellow]{sev_str}[/yellow]"
            else:
                sev_formatted = f"[blue]{sev_str}[/blue]"

            table.add_row(
                sev_formatted,
                escape(finding.rule_id),
                escape(f"{finding.resource.type}.{finding.resource.name}"),
                escape(str(finding.exposure)),
                escape(finding.message),
            )

        console.print(table)
        if unresolved_count > 0:
            console.print(f"[yellow]{unresolved_count} attributes could not be resolved[/yellow]")
        console.print("[dim]Note: Z (years to CRQC) is an assumption, not a prediction.[/dim]\n")
    else:
        out_path = output or Path(DEFAULT_REPORT_FILES[fmt])
        if fmt == "json":
            export_json(scan_result, out_path)
        elif fmt == "sarif":
            export_sarif(scan_result, out_path)
        elif fmt == "cbom":
            export_cbom(scan_result, out_path)
        elif fmt == "markdown":
            export_markdown(scan_result, out_path)
        console.print(f"[green]Report exported to {out_path}[/green]")

    # 7. Exit code calculation based on --fail-on threshold
    threshold = SEVERITY_RANK.get(fail_on.lower(), SEVERITY_RANK["high"])
    has_failing_findings = any(
        SEVERITY_RANK.get(f.severity.lower(), 0) >= threshold for f in findings
    )
    if has_failing_findings:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command("version")
def version():
    """Show the pqlint version."""
    console.print(f"pqlint version: {__version__}")


if __name__ == "__main__":
    app()
