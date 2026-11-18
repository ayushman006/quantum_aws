"""Exception hierarchy for pqlint."""

from typing import Optional


class PqlintError(Exception):
    """Base exception for all pqlint errors."""


class RedactionLeakError(PqlintError):
    """Raised when the fail-closed redaction leak guard detects an unmasked account ID.

    To prevent security leaks, this exception message NEVER contains the leaking
    account ID, the matching ARN, or surrounding text. It only reports a count
    and diagnostic summary.
    """

    def __init__(self, count: int = 1, context: Optional[str] = None) -> None:
        self.count = count
        self.context = context
        msg = f"Redaction leak guard tripped: {count} unmasked account-ID-like value(s) detected. No output was written."
        if context:
            msg += f" Target context: {context}."
        super().__init__(msg)
