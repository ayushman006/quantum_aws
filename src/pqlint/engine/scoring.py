"""Mosca inequality risk scorer for pqlint findings.

Evaluates post-quantum cryptographic risk based on the Mosca theorem:
- For Confidentiality (HNDL): Risk if X + Y > Z (shelf life + migration time > CRQC arrival).
- For Authenticity (Signatures): Risk if Y > Z (migration time > CRQC arrival).

If risk condition is met, preserves finding's base severity.
If risk condition is not met, downgrades severity to INFO.
Appends mathematical explanation to finding.message and populates finding.mosca.
"""

from typing import Any, List, Tuple, Union

from pqlint.config import DEFAULT_CONFIG
from pqlint.model import ExposureType, Finding, MoscaScore, Severity


def _fmt(val: Union[int, float]) -> str:
    """Format numeric values cleanly (e.g. 10 instead of 10.0)."""
    if isinstance(val, float) and val.is_integer():
        return str(int(val))
    return str(val)


def _extract_xyz(config: Any) -> Tuple[Union[int, float], Union[int, float], Union[int, float]]:
    """Extract X, Y, Z parameters from Config, dict, or object."""
    if config is None:
        return (
            DEFAULT_CONFIG.shelf_life_years,
            DEFAULT_CONFIG.migration_years,
            DEFAULT_CONFIG.crqc_years,
        )

    if isinstance(config, dict):
        raw_x = config.get("shelf_life_years", config.get("X", DEFAULT_CONFIG.shelf_life_years))
        raw_y = config.get("migration_years", config.get("Y", DEFAULT_CONFIG.migration_years))
        raw_z = config.get("crqc_years", config.get("Z", DEFAULT_CONFIG.crqc_years))
    else:
        raw_x = getattr(
            config, "shelf_life_years", getattr(config, "X", DEFAULT_CONFIG.shelf_life_years)
        )
        raw_y = getattr(
            config, "migration_years", getattr(config, "Y", DEFAULT_CONFIG.migration_years)
        )
        raw_z = getattr(config, "crqc_years", getattr(config, "Z", DEFAULT_CONFIG.crqc_years))

    x: Union[int, float] = (
        raw_x if isinstance(raw_x, (int, float)) else DEFAULT_CONFIG.shelf_life_years
    )
    y: Union[int, float] = (
        raw_y if isinstance(raw_y, (int, float)) else DEFAULT_CONFIG.migration_years
    )
    z: Union[int, float] = raw_z if isinstance(raw_z, (int, float)) else DEFAULT_CONFIG.crqc_years
    return x, y, z


def evaluate_mosca_risk(finding: Finding, config: Any = None) -> Finding:
    """
    Evaluate a single Finding using the Mosca inequality risk model.

    Args:
        finding: Input Finding object.
        config: Config instance, dict, or None (defaults to DEFAULT_CONFIG).

    Returns:
        A new Finding with adjusted severity, structured MoscaScore, and appended explanation.
    """
    scored = finding.model_copy(deep=True)
    if scored.severity == Severity.UNKNOWN:
        base_msg = scored.message.strip() if scored.message else ""
        note = "(Mosca risk evaluation skipped: attribute resolution unknown)"
        scored.message = f"{base_msg} {note}" if base_msg else note
        scored.mosca = None
        return scored

    X, Y, Z = _extract_xyz(config)

    # Per-resource tag overrides for shelf life (X)
    raw_tags = finding.resource.attributes.get("tags", {})
    if isinstance(raw_tags, dict):
        for k, v in raw_tags.items():
            if str(k).lower() in ("pqlint_shelf_life", "mosca_x"):
                try:
                    if v is not None:
                        X = int(v)
                        break
                except (ValueError, TypeError):
                    pass
    elif isinstance(raw_tags, list):
        for item in raw_tags:
            if isinstance(item, dict):
                k = item.get("key", item.get("Key", ""))
                v = item.get("value", item.get("Value", ""))
                if str(k).lower() in ("pqlint_shelf_life", "mosca_x"):
                    try:
                        if v is not None:
                            X = int(v)
                            break
                    except (ValueError, TypeError):
                        pass

    if scored.exposure == ExposureType.CONFIDENTIALITY:
        # Confidentiality: Harvest-Now-Decrypt-Later risk if X + Y > Z
        is_at_risk = (X + Y) > Z
        operator = ">" if is_at_risk else "<="
        explanation = f"Mosca score: X ({_fmt(X)}) + Y ({_fmt(Y)}) {operator} Z ({_fmt(Z)}). Z is an assumption, not a prediction."
        x_val = int(round(X)) if X is not None else None
        scored.mosca = MoscaScore(
            x=x_val,
            y=int(round(Y)),
            z=int(round(Z)),
            at_risk=is_at_risk,
        )
    else:
        # Authenticity: Shelf life X does not apply to signatures. Risk if Y > Z
        is_at_risk = Y > Z
        operator = ">" if is_at_risk else "<="
        explanation = f"Mosca score: Y ({_fmt(Y)}) {operator} Z ({_fmt(Z)}). Z is an assumption, not a prediction."
        scored.mosca = MoscaScore(
            x=None,
            y=int(round(Y)),
            z=int(round(Z)),
            at_risk=is_at_risk,
        )

    # If condition is not met, downgrade severity to INFO; otherwise keep base severity
    if not is_at_risk:
        scored.severity = Severity.INFO

    # Append explanation to finding.message
    base_msg = scored.message.strip() if scored.message else ""
    if base_msg:
        scored.message = f"{base_msg} {explanation}"
    else:
        scored.message = explanation

    return scored


def score_findings(findings: List[Finding], config: Any = None) -> List[Finding]:
    """
    Score a list of findings using the Mosca inequality risk model.

    Args:
        findings: Collection of Finding objects.
        config: Config instance, dict, or None (defaults to DEFAULT_CONFIG).

    Returns:
        List of new Finding objects with Mosca risk-evaluated severity and explanations.
    """
    return [evaluate_mosca_risk(f, config) for f in findings]
