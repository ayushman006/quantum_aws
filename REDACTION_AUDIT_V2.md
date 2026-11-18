# Adversarial Security Audit Report: Redaction Layer & ScanResult Model (V2)

**Document ID:** PQL-SEC-AUD-002  
**Target:** `src/pqlint/redaction.py` & `src/pqlint/model.py`  
**Auditor:** Principal Application Security Auditor  
**Date:** 14 November 2026  
**Classification:** Security Assessment  
**Final Verdict:** NO-GO (Blocker for Step 2)

---

## 1. Executive Summary

A comprehensive adversarial security audit was performed against the revised redaction subsystem (`src/pqlint/redaction.py`) and top-level data model (`ScanResult` in `src/pqlint/model.py`). The objective was to verify strict adherence to the project's zero-leak hard constraint (PRD FR-60 through FR-65), ensuring that no AWS account ID can escape to terminal outputs, JSON, SARIF, or CBOM artifacts under any syntactic, structural, or encoding permutation.

The audit revealed three critical vulnerabilities and two design defects that allow raw 12-digit AWS account IDs to bypass detection, evade redaction, and silently circumvent the fail-closed leak guard:

1. **Word-Boundary Regex Failure:** The standalone fallback pattern `STANDALONE_12DIGIT_PATTERN = re.compile(r"\b(\d{12})\b")` relies on ASCII word boundaries `\b`. Under Python regex semantics, `\b` fails when adjacent to any word character `\w` (`[a-zA-Z0-9_]`). This causes immediate bypasses for snake_case identifiers (e.g., `account_123456789012`, `key_123456789012_prod`), alphanumeric prefixes, and URL-encoded strings (e.g., `%3A123456789012%3A`).
2. **Integer Dictionary Key Omission in Nested Structures:** In deeply nested attribute structures, dictionary keys of type `int` (e.g., `{123456789012: "dev"}`) are completely skipped during discovery and value traversal. When serialized by `model_dump_json()`, they are coerced to string keys (`{"123456789012": "dev"}`), leaking unmasked IDs directly into output.
3. **Tautological Fail-Closed Leak Guard:** The leak guard at the exit of `redact_scan_result()` validates only `for original_id in discovered_ids:`. Furthermore, line 224 performs an early exit if `not discovered_ids`. If Pass 1 fails to detect an account ID due to pattern or type omissions, the guard is entirely bypassed, rendering it blind to undiscovered leaks.

Because raw account IDs can leak in common Terraform constructs without triggering the leak guard, the system fails the zero-leak guarantee. **The final audit conclusion is NO-GO.**

---

## 2. Attack Vector Analysis

### 2.1 Vector 1: Regex Engine Analysis & Bypasses

#### 2.1.1 The Word-Boundary (`\b`) Flaw
In Python's `re` module, `\b` is defined as the zero-width boundary between a word character `\w` (`[a-zA-Z0-9_]`) and a non-word character `\W`. 

`src/pqlint/redaction.py` defined the fallback pattern as:
```python
STANDALONE_12DIGIT_PATTERN = re.compile(r"\b(\d{12})\b")
```

When evaluated against Terraform configurations containing identifiers or tags formatted in standard snake_case, the boundary check fails:
- Input: `"account_123456789012"`
  - Character before `1` is `_` (`\w`).
  - Transition `\w` to `\w` is not a word boundary.
  - Result: `STANDALONE_12DIGIT_PATTERN.search()` returns `None`.
- Input: `"123456789012_suffix"`
  - Character after `2` is `_` (`\w`).
  - Result: `STANDALONE_12DIGIT_PATTERN.search()` returns `None`.

#### 2.1.2 URL-Encoded ARNs
In API Gateway parameters, S3 notification configs, and webhooks, ARNs frequently appear URL-encoded:
- Input: `"arn%3Aaws%3Akms%3Aus-east-1%3A123456789012%3Akey"`
  - `TOLERANT_ARN_PATTERN` fails because colons are `%3A`.
  - `STANDALONE_12DIGIT_PATTERN` fails because `%3A` ends with `'A'`, which is an ASCII letter (`\w`). Between `'A'` and `'1'`, there is no word boundary.
  - Result: Zero discovery. Raw ID leaks to output.

#### 2.1.3 JSON Unicode-Escaped Sequences
In raw policy documents or embedded JSON strings (e.g., `policy = "{\"Principal\": \"\\u0031\\u0032...\"}"`):
- Python represents the literal as `\u0031\u0032...`.
- `\d{12}` does not match `\u0031`. Downstream consumers that parse or decode unicode sequences receive the unmasked account ID.

#### 2.1.4 Multi-Line Strings
`TOLERANT_ARN_PATTERN` uses `[^:\s\"'<>`()]*` for partition, service, and region fields. If an ARN is split across lines with whitespace or a newline, `TOLERANT_ARN_PATTERN` correctly stops. However, if the 12-digit account ID sits on a line bounded by underscores or letters, the fallback fails as established in 2.1.1.

---

### 2.2 Vector 2: Type Coercion & Structural Traversal

#### 2.2.1 Integer Boundary Verification
`python-hcl2` parses unquoted numbers as Python integers. `redaction.py` checks:
```python
if 100_000_000_000 <= val <= 999_999_999_999:
```
- Exactly at `100_000_000_000` (minimum 12-digit integer): Evaluates to `True`. Correct.
- Exactly at `999_999_999_999` (maximum 12-digit integer): Evaluates to `True`. Correct.
- Boundary `99_999_999_999` (11 digits): Evaluates to `False`. Correct.
- Boundary `1_000_000_000_000` (13 digits): Evaluates to `False`. Correct.

#### 2.2.2 Unquoted Integers with Leading Zeros
AWS account IDs are 12-digit strings. Some valid AWS account IDs begin with one or more leading zeros (e.g., `012345678901`).
- If an author declares `account_id = "012345678901"`, it is parsed as a 12-digit string and masked.
- If an author declares `account_id = 012345678901` unquoted, Python integer literal parsing strips the leading zero, resulting in `12345678901` (11 digits, value `12_345_678_901`).
- Because `12_345_678_901 < 100_000_000_000`, the redactor currently ignores it. If an attribute key belongs to `KNOWN_ACCOUNT_ID_KEYS`, any integer with 10 to 12 digits must be zero-padded to 12 digits and registered for redaction.

#### 2.2.3 Integer Dictionary Keys in Deeply Nested Structures
While Pydantic enforces `Resource.attributes: Dict[str, Any]` at the top level, nested dictionaries within `Any` are permitted to have non-string keys:
```python
resource = Resource(
    type="aws_kms_key",
    name="test",
    attributes={"mapping": {123456789012: "dev"}},
    origin=Origin.IAC,
)
```
In `src/pqlint/redaction.py`:
- `_discover_account_ids_in_val` only inspected keys if `isinstance(k, str)`. Integer keys were ignored.
- `redact_value` only transformed keys if `isinstance(k, str)`. Integer keys were preserved as integers.
- On serialization (`model_dump_json()`), JSON standards require all object keys to be strings. Pydantic coerces `{123456789012: "dev"}` into `{"123456789012": "dev"}`.
- Result: Plaintext account ID in output with zero discovery and zero guard triggering.

---

### 2.3 Vector 3: Fail-Closed Leak Guard Audit

#### 2.3.1 Tautological Circular Dependency
Lines 247-254 of `src/pqlint/redaction.py` state:
```python
serialized = copied_result.model_dump_json()
for original_id in discovered_ids:
    if original_id in serialized:
        raise RuntimeError(...)
```
And line 224 states:
```python
if not discovered_ids:
    return copied_result
```

This architecture is fundamentally flawed:
1. **Self-Referential Verification:** The leak guard assumes Pass 1 discovery is infallible. It checks only whether the IDs it already knew about were masked. If Pass 1 suffers an evasion (due to word boundaries, encoding, or type omissions), `discovered_ids` does not contain the leaked ID.
2. **Early-Exit Short-Circuit:** When `not discovered_ids`, the function returns immediately without ever serializing or validating the model.
3. **Requirement:** A true fail-closed security boundary must perform independent post-serialization scanning on `serialized` using pattern heuristics (`re.search`) to verify that no raw account ID patterns survive, regardless of what Pass 1 discovered.

#### 2.3.2 Serialization Parity Across Reporters
`model_dump_json()` in Pydantic v2 utilizes `pydantic_core.to_json()`. While `model_dump_json()` accurately mirrors the structure of standard JSON exports, reporters such as SARIF and CBOM will construct custom dictionaries and invoke `json.dumps()`.
- Standard library `json.dumps()` escapes forward slashes (`/`) and non-ASCII characters differently than `pydantic_core`.
- To guarantee zero leakage across all downstream reporters, all fields inside `ScanResult` (strings, numbers, keys, lists, dicts) must be transformed structurally in the Python object graph, not merely in serialized JSON.

---

### 2.4 Vector 4: Immutability & Memory Safety Verification

Pydantic v2's `result.model_copy(deep=True)` invokes Python's standard `copy.deepcopy()` across all fields, including nested dictionaries, lists, and tuples within `Resource.attributes`.
- Verification test confirmed: Mutating nested structures in the copied `ScanResult` does not mutate the original `ScanResult`.
- Shared instances: If a `Finding` references the same `Resource` instance as `ScanResult.resources`, `model_copy(deep=True)` preserves object identity within the copied graph while completely isolating it from the source graph.
- Scope gap: `Finding.rule_title`, `Finding.remediation_ref`, and `Finding.references` were omitted from traversal in `redact_scan_result`. If a dynamic rule or reference cites an account ID, it would remain unredacted.

---

## 3. Findings Matrix

| Finding ID | Severity | Category | Description | Status |
|---|---|---|---|---|
| **SEC-01** | Critical | Regex Evasion | `\b(\d{12})\b` fails on snake_case and alphanumeric boundaries (`account_123456789012`). | Open |
| **SEC-02** | Critical | Type Coercion | Integer dictionary keys in nested attributes bypass discovery and leak on serialization. | Open |
| **SEC-03** | Critical | Defense-in-Depth | Fail-closed leak guard is tautological and bypassed when `discovered_ids` is empty. | Open |
| **SEC-04** | High | Encoding Evasion | URL-encoded ARNs (`%3A123456789012%3A`) evade discovery completely. | Open |
| **SEC-05** | Medium | Data Model Gap | `Finding.rule_title`, `remediation_ref`, and `references` omitted from redaction. | Open |
| **SEC-06** | Low | Dead Code | `KNOWN_ACCOUNT_ID_KEYS` defined but never utilized in discovery or validation. | Open |

---

## 4. Remediation Plan

To achieve compliance with PRD FR-60 through FR-65 and satisfy zero-leak constraints:

1. **Replace Word Boundaries with Non-Digit Lookarounds:**
   Change fallback discovery pattern from `\b(\d{12})\b` to `(?<!\d)(\d{12})(?!\d)`. This matches 12-digit numbers regardless of whether they are bounded by whitespace, punctuation, underscores, or letters.
2. **Implement Pre-Discovery URL & Unicode Decoding:**
   Scan both raw strings and unquoted strings (`urllib.parse.unquote`) so URL-encoded account IDs are detected and registered.
3. **Traverse All Dictionary Keys Regardless of Type:**
   Inspect and redact dictionary keys whether they are `str` or `int`.
4. **Harden the Fail-Closed Leak Guard:**
   - Remove early exit `if not discovered_ids: return copied_result`.
   - Always serialize to JSON.
   - Assert zero occurrences of all `discovered_ids`.
   - Independently scan `serialized` with `(?<!\d)(\d{12})(?!\d)` and `TOLERANT_ARN_PATTERN`. Raise `RuntimeError` immediately if any unmasked 12-digit number (that is not a verified timestamp) is present.
5. **Utilize `KNOWN_ACCOUNT_ID_KEYS`:**
   Inspect attribute key names; if the key matches known account keys and contains a 10 to 12 digit integer (accounting for stripped leading zeros), pad and register it.
6. **Complete Field Coverage:**
   Include `finding.rule_title`, `finding.remediation_ref`, and `finding.references` in discovery and replacement.

---

## 5. Required Code Diff

Apply the following complete unified diff to `src/pqlint/redaction.py`:

```diff
--- a/src/pqlint/redaction.py
+++ b/src/pqlint/redaction.py
@@ -12,6 +12,7 @@
 import copy
 import re
+import urllib.parse
 from typing import Any, Dict, List, Optional, Set, Union
 
 from pqlint.model import Finding, Resource, ScanResult
@@ -33,8 +34,8 @@
 # Backward-compatible alias for ARN regex matching
 ARN_ACCOUNT_PATTERN = TOLERANT_ARN_REPLACE
 
-# Strict regex to find standalone 12-digit numbers
-STANDALONE_12DIGIT_PATTERN = re.compile(r"\b(\d{12})\b")
+# Non-digit boundary regex to find any 12-digit number (not limited by word characters \w)
+STANDALONE_12DIGIT_PATTERN = re.compile(r"(?<!\d)(\d{12})(?!\d)")
 
 # Known attribute keys that directly store an AWS account ID
 KNOWN_ACCOUNT_ID_KEYS = {
@@ -76,14 +77,22 @@
     if not text:
         return
 
-    # 1. Extract from tolerant ARNs (including Terraform interpolations like ${var.region})
-    for match in TOLERANT_ARN_PATTERN.finditer(text):
-        acct_id = match.group(1)
-        discovered_ids.add(acct_id)
-
-    # 2. Extract standalone 12-digit strings (fallback / embedded JSON)
-    for match in STANDALONE_12DIGIT_PATTERN.finditer(text):
-        candidate = match.group(1)
-        if not _is_likely_timestamp(candidate, key_name):
-            discovered_ids.add(candidate)
+    # Scan both raw text and URL-unquoted text to catch encoded ARNs/IDs
+    candidates = [text]
+    try:
+        unquoted = urllib.parse.unquote(text)
+        if unquoted != text:
+            candidates.append(unquoted)
+    except Exception:
+        pass
+
+    for candidate_str in candidates:
+        # 1. Extract from tolerant ARNs
+        for match in TOLERANT_ARN_PATTERN.finditer(candidate_str):
+            discovered_ids.add(match.group(1))
+
+        # 2. Extract non-digit bounded 12-digit strings
+        for match in STANDALONE_12DIGIT_PATTERN.finditer(candidate_str):
+            candidate_id = match.group(1)
+            if not _is_likely_timestamp(candidate_id, key_name):
+                discovered_ids.add(candidate_id)
 
 
 def _discover_account_ids_in_val(val: Any, discovered_ids: Set[str], key_name: Optional[str] = None) -> None:
@@ -91,19 +100,31 @@
     if isinstance(val, str):
         _discover_account_ids_in_str(val, discovered_ids, key_name)
     elif isinstance(val, int) and not isinstance(val, bool):
-        # python-hcl2 parses unquoted numbers as integers
+        # Handle standard 12-digit integers
         if 100_000_000_000 <= val <= 999_999_999_999:
             val_str = str(val)
             if not _is_likely_timestamp(val_str, key_name):
                 discovered_ids.add(val_str)
+        # Handle stripped leading zeros in known account ID fields
+        elif key_name and key_name.lower() in KNOWN_ACCOUNT_ID_KEYS and 0 <= val <= 999_999_999_999:
+            val_str = f"{val:012d}"
+            if not _is_likely_timestamp(val_str, key_name):
+                discovered_ids.add(val_str)
     elif isinstance(val, dict):
         for k, v in val.items():
             if isinstance(k, str):
                 _discover_account_ids_in_str(k, discovered_ids)
-            _discover_account_ids_in_val(v, discovered_ids, k if isinstance(k, str) else None)
+            elif isinstance(k, int) and not isinstance(k, bool):
+                _discover_account_ids_in_val(k, discovered_ids, key_name="account_id")
+            _discover_account_ids_in_val(v, discovered_ids, str(k))
     elif isinstance(val, (list, tuple, set)):
         for item in val:
             _discover_account_ids_in_val(item, discovered_ids, key_name)
 
 
 def redact_text(text: Optional[str], account_map: Dict[str, str]) -> Optional[str]:
@@ -148,8 +169,12 @@
     elif isinstance(val, int) and not isinstance(val, bool):
         # Convert 12-digit integers to redacted string placeholders
         if 100_000_000_000 <= val <= 999_999_999_999:
             val_str = str(val)
             if val_str in account_map:
                 return account_map[val_str]
+        val_padded = f"{val:012d}"
+        if val_padded in account_map:
+            return account_map[val_padded]
         return val
     elif isinstance(val, dict):
         redacted_dict: Dict[str, Any] = {}
         for k, v in val.items():
-            k_redacted = redact_text(k, account_map) if isinstance(k, str) else k
+            if isinstance(k, str):
+                k_redacted = redact_text(k, account_map)
+            elif isinstance(k, int) and not isinstance(k, bool):
+                k_redacted = redact_value(k, account_map)
+            else:
+                k_redacted = k
             redacted_dict[k_redacted] = redact_value(v, account_map)
         return redacted_dict
 
@@ -216,6 +241,11 @@
     for f in copied_result.findings:
         _discover_account_ids_in_str(f.message, discovered_ids)
+        _discover_account_ids_in_str(f.rule_title, discovered_ids)
+        _discover_account_ids_in_str(f.remediation_ref, discovered_ids)
+        for ref in f.references:
+            _discover_account_ids_in_str(ref, discovered_ids)
         _discover_account_ids_in_str(f.resource.name, discovered_ids)
         _discover_account_ids_in_str(f.resource.source_location, discovered_ids)
         _discover_account_ids_in_str(f.resource.provider_id, discovered_ids)
         _discover_account_ids_in_val(f.resource.attributes, discovered_ids)
 
@@ -223,8 +253,8 @@
     for w in copied_result.warnings:
         _discover_account_ids_in_str(w, discovered_ids)
 
-    if not discovered_ids:
-        return copied_result
-
     # 3. Determinism: Alphanumerically sort discovered IDs before assigning placeholders
     sorted_ids = sorted(list(discovered_ids))
     account_map: Dict[str, str] = {
@@ -236,11 +266,16 @@
     for r in copied_result.resources:
         redact_resource(r, account_map)
 
     for f in copied_result.findings:
         if f.message:
             f.message = redact_text(f.message, account_map) or f.message
+        if f.rule_title:
+            f.rule_title = redact_text(f.rule_title, account_map) or f.rule_title
+        if f.remediation_ref:
+            f.remediation_ref = redact_text(f.remediation_ref, account_map)
+        if f.references:
+            f.references = [redact_text(ref, account_map) or ref for ref in f.references]
         redact_resource(f.resource, account_map)
 
     if copied_result.warnings:
         copied_result.warnings = [
             redact_text(w, account_map) or w for w in copied_result.warnings
         ]
 
-    # 5. Fail-Closed Leak Guard: serialize to JSON and verify zero discovered IDs remain
+    # 5. Fail-Closed Leak Guard: Serialize and run dual-pass verification
     serialized = copied_result.model_dump_json()
+    # Check 5a: Zero discovered original IDs survive
     for original_id in discovered_ids:
         if original_id in serialized:
             raise RuntimeError(
                 f"Security leak detected: Discovered AWS account ID '{original_id}' "
                 f"was found in serialized output after redaction. Aborting execution."
             )
+
+    # Check 5b: Independent scan for any unmasked 12-digit number or tolerant ARN pattern
+    for match in STANDALONE_12DIGIT_PATTERN.finditer(serialized):
+        candidate = match.group(1)
+        if not _is_likely_timestamp(candidate):
+            raise RuntimeError(
+                f"Security leak detected: Unredacted 12-digit number '{candidate}' "
+                f"detected in serialized output. Aborting execution."
+            )
+
+    for match in TOLERANT_ARN_PATTERN.finditer(serialized):
+        raise RuntimeError(
+            f"Security leak detected: Unredacted ARN structure '{match.group(0)}' "
+            f"detected in serialized output. Aborting execution."
+        )
 
     return copied_result
```

---

## 6. Conclusion & Audit Decision

### Audit Verdict: **NO-GO**

Forward development on Step 2 (UNKNOWN variable handling) must remain halted until the attached patch is applied to `src/pqlint/redaction.py` and regression tests covering snake_case identifiers, URL-encoded ARNs, integer dictionary keys, and independent leak guard triggering pass with 100% success.
