"""Safe identifier generation for pqlint findings, CBOM refs, and fingerprints.

Guarantees that generated identifiers can NEVER contain a run of 12 consecutive
digits, preventing false-positive trips in the fail-closed leak guard.
"""

import base64
import hashlib
import os
import re

DIGIT_12_RUN_PATTERN = re.compile(r"\d{12}")

# Lowercase base32 characters (RFC 4648: a-z and digits 2-7)
# Note that digits 0, 1, 8, and 9 do not exist in standard RFC 4648 Base32.


def generate_safe_id(prefix: str = "pql", num_bytes: int = 16) -> str:
    """Generate a random unique identifier guaranteed to contain no 12-digit runs.

    Uses a letter prefix and lowercase base32 encoding, looping until the
    resulting string contains no run of 12 consecutive digits.
    """
    clean_prefix = re.sub(r"[^a-zA-Z0-9_-]", "", prefix).lower()
    if not clean_prefix or not clean_prefix[0].isalpha():
        clean_prefix = f"pql-{clean_prefix}"

    while True:
        raw_bytes = os.urandom(num_bytes)
        encoded = base64.b32encode(raw_bytes).decode("ascii").rstrip("=").lower()
        candidate = f"{clean_prefix}-{encoded}"
        if not DIGIT_12_RUN_PATTERN.search(candidate):
            return candidate


def generate_deterministic_id(seed_text: str, prefix: str = "pql") -> str:
    """Generate a deterministic identifier from a seed string guaranteed to contain no 12-digit runs.

    Computes SHA-256 and encodes to lowercase base32. If a 12-digit run is found,
    salts with an incremental counter until clean.
    """
    clean_prefix = re.sub(r"[^a-zA-Z0-9_-]", "", prefix).lower()
    if not clean_prefix or not clean_prefix[0].isalpha():
        clean_prefix = f"pql-{clean_prefix}"

    counter = 0
    while True:
        to_hash = seed_text if counter == 0 else f"{seed_text}:{counter}"
        digest = hashlib.sha256(to_hash.encode("utf-8")).digest()
        encoded = base64.b32encode(digest[:16]).decode("ascii").rstrip("=").lower()
        candidate = f"{clean_prefix}-{encoded}"
        if not DIGIT_12_RUN_PATTERN.search(candidate):
            return candidate
        counter += 1
