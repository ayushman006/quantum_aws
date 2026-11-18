"""AWS account ID redaction layer for pqlint scan results.

Intercepts all scan outputs (resources, findings, warnings) to structurally mask
12-digit AWS account IDs into deterministic, sorted placeholders (ACCT-1, ACCT-2, ...)
before they reach reporters, terminal output, or disk.

Threat Model & Scope:
- In scope: Accidental exposure of AWS account IDs in infrastructure-as-code files,
  ARNs, Terraform variable interpolations, snake_case identifiers, URL-encoded ARNs,
  nested attributes, and unquoted integers.
- Out of scope: Intentional adversarial evasion techniques such as Unicode-escape
  encoding (e.g., \\u0031), base64 encoding, or HTML-entity encoding. The threat
  model addresses accidental exposure in CI/CD artifacts, not active steganography.

Includes a fail-closed leak guard (Redactor.verify) that unconditionally verifies
final rendered outputs (JSON, SARIF, CBOM, Markdown, tables) and aborts execution
with a value-free RedactionLeakError if any unmasked account ID is detected.
"""

import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set

from pqlint.errors import RedactionLeakError
from pqlint.model import Finding, Resource, ScanResult

# Tolerant regex to match AWS ARNs and extract the 12-digit account ID.
# Tolerates Terraform interpolations like ${var.region} in partition, service, or region fields.
# Format: arn:<partition>:<service>:<region>:<account_id>:<resource>
TOLERANT_ARN_PATTERN = re.compile(
    r"arn:[^:\s\"'<>`()]*:[^:\s\"'<>`()]*:[^:\s\"'<>`()]*:(\d{12})(?::|$|[^\w])",
    re.IGNORECASE,
)

# Replace regex for tolerant ARNs:
# Group 1: Prefix up to account ID, e.g. "arn:aws:kms:${var.region}:"
# Group 2: 12-digit account ID, e.g. "123456789012"
# Group 3: Suffix starting with colon or end of ARN
TOLERANT_ARN_REPLACE = re.compile(
    r"(arn:[^:\s\"'<>`()]*:[^:\s\"'<>`()]*:[^:\s\"'<>`()]*:)(\d{12})(:[^\s\"'<>`(),\]]*|$)",
    re.IGNORECASE,
)

# Backward-compatible alias for ARN regex matching
ARN_ACCOUNT_PATTERN = TOLERANT_ARN_REPLACE

# Single digit-boundary pattern for bare 12-digit IDs.
# Matches 12 digits not flanked by other digits, correctly matching next to
# word characters like underscores (snake_case) or URL-encoded boundaries.
STANDALONE_12DIGIT_PATTERN = re.compile(r"(?<!\d)(\d{12})(?!\d)")

# Known attribute keys that directly store an AWS account ID (exact lowercase match)
KNOWN_ACCOUNT_ID_KEYS = {
    "account_id",
    "account",
    "owner_id",
    "aws_account_id",
    "target_account_id",
    "source_account",
    "accountid",
}


def redact_text(text: Optional[str], account_map: Optional[Dict[str, str]] = None) -> Optional[str]:
    """Redact account IDs in ARNs and non-ARN text using the account map.

    If account_map is omitted or None, automatically discovers 12-digit account IDs
    in the text and generates sorted deterministic ACCT-N placeholders.
    """
    if text is None:
        return None
    if not text:
        return text

    if account_map is None:
        discovered: Set[str] = set()
        _discover_account_ids(text, discovered)
        if not discovered:
            return text
        account_map = {
            acct_id: f"ACCT-{idx}" for idx, acct_id in enumerate(sorted(list(discovered)), start=1)
        }

    for acct_id, placeholder in account_map.items():
        pattern = rf"(?<!\d){re.escape(acct_id)}(?!\d)"
        text = re.sub(pattern, placeholder, text)
    return text


def _discover_account_ids(val: Any, discovered: Set[str], key_name: Optional[str] = None) -> None:
    """Recursively discover account IDs from arbitrary data structures."""
    if isinstance(val, str):
        candidates = [val]
        try:
            unquoted = urllib.parse.unquote(val)
            if unquoted != val:
                candidates.append(unquoted)
        except Exception:
            pass

        for text in candidates:
            # 1. Discover from tolerant ARNs
            for match in TOLERANT_ARN_PATTERN.finditer(text):
                discovered.add(match.group(1))

            # 2. Discover from bare 12-digit runs
            for match in STANDALONE_12DIGIT_PATTERN.finditer(text):
                discovered.add(match.group(1))

    elif isinstance(val, int) and not isinstance(val, bool):
        # Full 12-digit integer (100_000_000_000 .. 999_999_999_999)
        if 100_000_000_000 <= val <= 999_999_999_999:
            discovered.add(str(val))
        # Unquoted integer with stripped leading zero under known account key (val >= 10**9)
        elif key_name and key_name.lower() in KNOWN_ACCOUNT_ID_KEYS and 10**9 <= val < 10**12:
            discovered.add(f"{val:012d}")

    elif isinstance(val, dict):
        for k, v in val.items():
            # Discover from dictionary keys
            if isinstance(k, str):
                _discover_account_ids(k, discovered)
            elif isinstance(k, int) and not isinstance(k, bool):
                _discover_account_ids(k, discovered)
            # Discover from dictionary values
            _discover_account_ids(v, discovered, key_name=str(k))

    elif isinstance(val, (list, tuple, set)):
        for item in val:
            _discover_account_ids(item, discovered, key_name=key_name)


def _redact_value(val: Any, account_map: Dict[str, str], key_name: Optional[str] = None) -> Any:
    """Recursively redact arbitrary values, integers, and dictionary keys."""
    if isinstance(val, str):
        return redact_text(val, account_map)
    elif isinstance(val, int) and not isinstance(val, bool):
        if 100_000_000_000 <= val <= 999_999_999_999:
            val_str = str(val)
            if val_str in account_map:
                return account_map[val_str]
        elif key_name and key_name.lower() in KNOWN_ACCOUNT_ID_KEYS and 10**9 <= val < 10**12:
            padded_str = f"{val:012d}"
            if padded_str in account_map:
                return account_map[padded_str]
        return val
    elif isinstance(val, dict):
        redacted_dict: Dict[Any, Any] = {}
        for k, v in val.items():
            new_k: Any = k
            if isinstance(k, str):
                new_k = redact_text(k, account_map)
            elif isinstance(k, int) and not isinstance(k, bool):
                if 100_000_000_000 <= k <= 999_999_999_999:
                    k_str = str(k)
                    new_k = account_map.get(k_str, k)
            redacted_dict[new_k] = _redact_value(v, account_map, key_name=str(k))
        return redacted_dict
    elif isinstance(val, list):
        return [_redact_value(item, account_map, key_name) for item in val]
    elif isinstance(val, tuple):
        return tuple(_redact_value(item, account_map, key_name) for item in val)
    elif isinstance(val, set):
        return {_redact_value(item, account_map, key_name) for item in val}
    return val


def redact_resource(resource: Resource, account_map: Dict[str, str]) -> None:
    """Mutate a copied Resource in place with redacted fields."""
    if resource.name:
        resource.name = redact_text(resource.name, account_map) or resource.name
    if resource.location and resource.location.file_path:
        redacted_fp = redact_text(resource.location.file_path, account_map)
        if redacted_fp is not None:
            resource.location.file_path = redacted_fp
    elif resource.source_location:
        resource.source_location = redact_text(resource.source_location, account_map)
    if resource.provider_id:
        resource.provider_id = redact_text(resource.provider_id, account_map)
    if resource.attributes:
        resource.attributes = _redact_value(resource.attributes, account_map)


class Redactor:
    """Stateful redaction engine that masks account IDs and verifies rendered outputs."""

    __slots__ = ("__discovered_ids",)

    def __init__(self) -> None:
        self.__discovered_ids: Set[str] = set()

    def __repr__(self) -> str:
        return f"<Redactor discovered_count={len(self.__discovered_ids)}>"

    def redact(self, scan_result: ScanResult) -> ScanResult:
        """Structurally redact all account IDs across the full object graph of a ScanResult."""
        # Generic traversal: dump to dict to ensure all fields (current & future) are visited
        raw_data = scan_result.model_dump()

        # Pass 1: Discover all account IDs
        self.__discovered_ids.clear()
        _discover_account_ids(raw_data, self.__discovered_ids)

        if not self.__discovered_ids:
            return scan_result.model_copy(deep=True)

        # Deterministic sorting before assigning placeholders
        sorted_ids = sorted(list(self.__discovered_ids))
        account_map: Dict[str, str] = {
            acct_id: f"ACCT-{idx}" for idx, acct_id in enumerate(sorted_ids, start=1)
        }

        # Pass 2: Redact the full dictionary structure
        redacted_data = _redact_value(raw_data, account_map)

        # Re-validate back into ScanResult
        return ScanResult.model_validate(redacted_data)

    def verify(self, rendered: str) -> None:
        """Fail-closed leak guard that inspects final rendered text for unredacted account IDs.

        Always executes unconditionally. Validates both against discovered IDs and
        performs independent pattern scans for bare 12-digit runs and tolerant ARNs.

        Raises:
            RedactionLeakError: If any unmasked account ID pattern is detected.
                                The exception message NEVER includes the raw value.
        """
        leak_count = 0
        detected_spans: Set[str] = set()

        # Check (a): Ensure none of the discovered IDs (or URL-encoded variants) appear
        for acct_id in self.__discovered_ids:
            if acct_id in rendered:
                if acct_id not in detected_spans:
                    detected_spans.add(acct_id)
                    leak_count += 1
            encoded_id = urllib.parse.quote(acct_id)
            if encoded_id != acct_id and encoded_id in rendered:
                if encoded_id not in detected_spans:
                    detected_spans.add(encoded_id)
                    leak_count += 1

        # Check (b): Independent scan for any bare 12-digit number
        for match in STANDALONE_12DIGIT_PATTERN.finditer(rendered):
            val = match.group(1)
            if val not in detected_spans:
                detected_spans.add(val)
                leak_count += 1

        # Check (c): Independent scan for tolerant ARNs
        for match in TOLERANT_ARN_PATTERN.finditer(rendered):
            val = match.group(1)
            if val not in detected_spans:
                detected_spans.add(val)
                leak_count += 1

        if leak_count > 0:
            raise RedactionLeakError(count=leak_count)


def redact_scan_result(result: ScanResult, enabled: bool = True) -> ScanResult:
    """
    Structurally redact AWS account IDs from an entire ScanResult.

    Args:
        result: The top-level ScanResult wrapper.
        enabled: If True (default), masks 12-digit account IDs with deterministic,
                 alphanumerically sorted placeholders (ACCT-1, ACCT-2, ...).
                 If False (--no-redact), returns an unmasked deep copy.

    Returns:
        A deep copy of the ScanResult with all account IDs redacted.

    Raises:
        RedactionLeakError: If any discovered or unmasked account ID remains present
                            in the final serialized JSON output (fail-closed leak guard).
    """
    if not enabled:
        return result.model_copy(deep=True)

    redactor = Redactor()
    redacted = redactor.redact(result)
    # Fail-closed leak guard unconditionally verifies model_dump_json()
    redactor.verify(redacted.model_dump_json())
    return redacted


def redact_findings(findings: List[Finding], enabled: bool = True) -> List[Finding]:
    """Backward-compatible helper that redacts a list of Finding objects."""
    if not findings:
        return []
    scan_result = ScanResult(findings=findings)
    redacted = redact_scan_result(scan_result, enabled=enabled)
    return redacted.findings
