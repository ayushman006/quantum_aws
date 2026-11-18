"""Remediation engine for post-quantum upgrade recommendations (Milestone 3)."""

from pathlib import Path
from typing import Any, Optional

import yaml

from pqlint.model import Finding

DEFAULT_SUPPORT_MATRIX_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "aws_pq_support.yaml"
)


def suggest_remediation(
    finding: Finding,
    support_matrix_path: Path = DEFAULT_SUPPORT_MATRIX_PATH,
) -> Optional[str]:
    """Suggest a concise upgrade path based on the AWS PQ support matrix."""
    if not finding.remediation_ref:
        return None

    path = Path(support_matrix_path)
    if not path.is_file():
        return None

    try:
        content = path.read_text(encoding="utf-8")
        matrix = yaml.safe_load(content)
        if not isinstance(matrix, dict):
            return None
    except Exception:
        return None

    ref_data: Any = matrix.get(finding.remediation_ref)
    if not ref_data and "services" in matrix and isinstance(matrix["services"], dict):
        ref_data = matrix["services"].get(finding.remediation_ref)

    if not ref_data:
        return None

    if isinstance(ref_data, dict):
        if "suggestion" in ref_data:
            return str(ref_data["suggestion"])
        if "recommended_policy" in ref_data:
            return f"Upgrade to {ref_data['recommended_policy']}."
        if "policies" in ref_data and isinstance(ref_data["policies"], list):
            return f"Upgrade to supported policy: {', '.join(ref_data['policies'])}."
    elif isinstance(ref_data, str):
        return ref_data

    return None
