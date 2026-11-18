"""Independent red-team check for pqlint's redaction layer.

Run from the repo root, AFTER `pip install -e ".[dev]"`:

    python redteam_redaction.py

It uses only the public API (ScanResult, Resource, Finding, redact_scan_result,
Redactor, RedactionLeakError) and the fake account IDs below. It never prints
an ID, only PASS/FAIL labels. Exit code 0 = all checks passed, 1 = failures.

This is deliberately separate from the agent's own tests, so a test written to
pass cannot hide a real gap.
"""

import random
import sys
import traceback
import uuid

try:
    from pqlint.model import ExposureType, Finding, Origin, Resource, ScanResult, Severity
    from pqlint.redaction import redact_scan_result
except Exception as exc:  # noqa: BLE001
    print("FATAL: cannot import pqlint public API:", type(exc).__name__)
    sys.exit(2)

try:
    from pqlint.redaction import Redactor
except Exception:  # noqa: BLE001
    Redactor = None  # type: ignore

try:
    from pqlint.errors import RedactionLeakError
except Exception:  # noqa: BLE001
    RedactionLeakError = Exception  # type: ignore

ID = "123456789012"  # fake
ID2 = "210987654321"  # fake
ID0 = "012345678901"  # fake, leading zero

results = []


def record(label, ok):
    results.append((label, ok))
    print(("PASS  " if ok else "FAIL  ") + label)


def make(
    attrs=None,
    msg="m",
    name="x",
    loc="main.tf:1",
    pid=None,
    title="t",
    ref=None,
    refs=None,
    warn=None,
    rule_id="R",
):
    r = Resource(
        type="aws_kms_key",
        name=name,
        attributes=attrs or {},
        source_location=loc,
        provider_id=pid,
        origin=Origin.IAC,
    )
    f = Finding(
        rule_id=rule_id,
        rule_title=title,
        resource=r,
        severity=Severity.HIGH,
        exposure=ExposureType.AUTHENTICITY,
        message=msg,
        remediation_ref=ref,
        references=refs or [],
    )
    return ScanResult(resources=[r], findings=[f], warnings=warn or [])


def dump(sr):
    return sr.model_dump_json()


def no_leak(label, secret=ID, **kw):
    try:
        out = dump(redact_scan_result(make(**kw)))
        record(label, secret not in out)
    except Exception as e:  # noqa: BLE001
        record(label + "  (raised %s)" % type(e).__name__, False)


# ---- 1. Leak cases (every one must be masked) -------------------------------
no_leak("interpolated region ARN", attrs={"k": "arn:aws:kms:${var.region}:%s:key/x" % ID})
no_leak(
    "interpolated partition ARN",
    attrs={"k": "arn:${data.aws_partition.current.partition}:iam::%s:root" % ID},
)
no_leak("iam ARN, empty region", attrs={"k": "arn:aws:iam::%s:root" % ID})
no_leak("ARN ends right after ID", attrs={"k": "arn:aws:kms:us-east-1:%s" % ID})
no_leak("GovCloud ARN", attrs={"k": "arn:aws-us-gov:kms:us-gov-west-1:%s:key/x" % ID})
no_leak("uppercase ARN", attrs={"k": "ARN:AWS:KMS:us-east-1:%s:key/x" % ID})
no_leak("int account_id", attrs={"account_id": int(ID)})
no_leak("list identifiers", attrs={"identifiers": [ID]})
no_leak("policy JSON string", attrs={"policy": '{"Principal":{"AWS":"%s"}}' % ID})
no_leak(
    "aws:SourceAccount condition", attrs={"Condition": {"StringEquals": {"aws:SourceAccount": ID}}}
)
no_leak("bare ID under unrelated key", attrs={"owner": ID})
no_leak("ID in message", msg="key in account %s bad" % ID)
no_leak("ID in resource name", name="role-%s" % ID)
no_leak("ID in file path", loc="accounts/%s/infra/main.tf:3" % ID)
no_leak("ID in provider_id", pid=ID)
no_leak("ID in warning", warn=["could not parse %s/main.tf" % ID])
no_leak("ID in rule_title", title="Key in %s" % ID)
no_leak("ID in remediation_ref", ref="fix-%s" % ID)
no_leak("ID in references", refs=["https://x/%s" % ID])
no_leak("ID in rule_id", rule_id="R-%s" % ID)
no_leak("snake_case prefix account_<id>", attrs={"n": "account_%s" % ID})
no_leak("snake_case suffix <id>_prod", attrs={"n": "%s_prod" % ID})
no_leak("hyphen bounded", attrs={"n": "id-%s-x" % ID})
no_leak(
    "URL-encoded ARN (upper %3A)", attrs={"k": "arn%%3Aaws%%3Akms%%3Aus-east-1%%3A%s%%3Akey" % ID}
)
no_leak(
    "URL-encoded ARN (lower %3a)", attrs={"k": "arn%%3aaws%%3akms%%3aus-east-1%%3a%s%%3akey" % ID}
)
no_leak("int dict key", attrs={"mapping": {int(ID): "dev"}})
no_leak("str dict key = ID", attrs={ID: "dev"})
no_leak("ARN as dict key", attrs={"arn:aws:kms:us-east-1:%s:key/x" % ID: "v"})
no_leak("nested list of dicts", attrs={"a": [{"b": [{"c": "x %s y" % ID}]}]})
no_leak("key validated_account_id", attrs={"validated_account_id": ID})
no_leak("key update_account", attrs={"update_account": ID})
no_leak("key created_by_account", attrs={"created_by_account": ID})
no_leak("int under key candidate_account", attrs={"candidate_account": int(ID)})
no_leak("timestamp-shaped ID 202611142045", secret="202611142045", msg="account 202611142045 bad")
no_leak("leading-zero string", secret=ID0, attrs={"account_id": ID0})
no_leak(
    "leading-zero int under account_id (11 digits shown)",
    secret="12345678901",
    attrs={"account_id": 12345678901},
)

# multiple IDs in one text
try:
    out = dump(redact_scan_result(make(msg="a %s b %s c" % (ID, ID2))))
    record("two different IDs in one message", ID not in out and ID2 not in out)
except Exception:  # noqa: BLE001
    record("two different IDs in one message (raised)", False)

# ---- 2. Must NOT be corrupted ----------------------------------------------
try:
    attrs = {
        "count": 0,
        "n": 1,
        "port": 443,
        "mapping": {0: "a", 1: "b"},
        "eleven": 12345678901,
        "epoch_ms": 1731600000000,
        "thirteen": "1%s" % ID,
    }
    out = redact_scan_result(make(attrs=attrs)).resources[0].attributes
    ok = (
        out["count"] == 0
        and out["n"] == 1
        and out["port"] == 443
        and out["mapping"].get(0) == "a"
        and out["mapping"].get(1) == "b"
        and out["epoch_ms"] == 1731600000000
        and out["thirteen"] == "1%s" % ID
    )
    record("small ints, ports, 13-digit values untouched", ok)
except Exception as e:  # noqa: BLE001
    record("small ints untouched (raised %s)" % type(e).__name__, False)

# ---- 3. Determinism and immutability ----------------------------------------
try:
    a = Resource(
        type="t",
        name="a",
        attributes={"k": "arn:aws:kms:us-east-1:111111111111:key/a"},
        origin=Origin.IAC,
    )
    b = Resource(
        type="t",
        name="b",
        attributes={"k": "arn:aws:kms:us-east-1:222222222222:key/b"},
        origin=Origin.IAC,
    )
    o1 = redact_scan_result(ScanResult(resources=[a, b]))
    o2 = redact_scan_result(ScanResult(resources=[b, a]))
    m1 = {r.name: r.attributes["k"] for r in o1.resources}
    m2 = {r.name: r.attributes["k"] for r in o2.resources}
    record("placeholders independent of input order", m1 == m2)
except Exception:  # noqa: BLE001
    record("determinism (raised)", False)

try:
    sr = make(attrs={"k": "arn:aws:kms:us-east-1:%s:key/x" % ID})
    before = dump(sr)
    redact_scan_result(sr)
    record("input ScanResult not mutated", dump(sr) == before)
except Exception:  # noqa: BLE001
    record("immutability (raised)", False)

try:
    sr = make(attrs={"k": "arn:aws:kms:us-east-1:%s:key/x" % ID})
    out = redact_scan_result(sr, enabled=False)
    record("--no-redact keeps data and returns a copy", ID in dump(out) and out is not sr)
except Exception:  # noqa: BLE001
    record("--no-redact (raised)", False)

# ---- 4. Guard behaviour ------------------------------------------------------
if Redactor is None:
    record("Redactor class exists", False)
else:
    try:
        red = Redactor()
        raised = False
        msg_ok = True
        try:
            red.verify('{"note": "account %s leaked"}' % ID)  # nothing was redacted yet
        except Exception as e:  # noqa: BLE001
            raised = True
            text = (
                str(e) + repr(e) + "".join(traceback.format_exception(type(e), e, e.__traceback__))
            )
            msg_ok = ID not in text
        record("verify() raises on a bare ID even if discovery found nothing", raised)
        record("guard error text never contains the ID (str/repr/traceback)", msg_ok)
        record(
            "guard raises RedactionLeakError specifically",
            RedactionLeakError is not Exception and raised,
        )
    except Exception as e:  # noqa: BLE001
        record("Redactor() usable with no args (raised %s)" % type(e).__name__, False)

    try:
        red = Redactor()
        red.redact(make(attrs={"k": "arn:aws:kms:us-east-1:%s:key/x" % ID}))
        exposed = repr(red) + str(getattr(red, "__dict__", ""))
        record("Redactor repr/__dict__ does not expose real IDs", ID not in exposed)
        raised = False
        try:
            red.verify("clean text with ACCT-1 only")
        except Exception:  # noqa: BLE001
            raised = True
        record("verify() accepts clean redacted text", not raised)
        raised = False
        try:
            red.verify("oops %s" % ID)
        except Exception:  # noqa: BLE001
            raised = True
        record("verify() rejects text containing the discovered ID", raised)
    except Exception as e:  # noqa: BLE001
        record("Redactor.redact/verify flow (raised %s)" % type(e).__name__, False)

# ---- 5. Invariant: random UUIDs / hex / EC2 IDs must never raise -------------
random.seed(7)
try:
    for _ in range(3000):
        u = str(uuid.UUID(int=random.getrandbits(128)))
        h = "".join(random.choice("0123456789abcdef") for _ in range(64))
        e = "i-" + "".join(random.choice("0123456789abcdef") for _ in range(17))
        redact_scan_result(
            make(attrs={"u": u, "h": h, "e": e, "arn": "arn:aws:kms:us-east-1:%s:key/%s" % (ID, u)})
        )
    record("3000 random UUID/hex/EC2 values never trip the guard", True)
except Exception as e:  # noqa: BLE001
    record("random UUID/hex/EC2 values (raised %s)" % type(e).__name__, False)

failed = [label for label, ok in results if not ok]
print("\n%d checks, %d failed" % (len(results), len(failed)))
sys.exit(1 if failed else 0)
