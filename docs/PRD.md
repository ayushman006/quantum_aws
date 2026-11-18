# PRD — pqlint: Open-Source Post-Quantum Readiness Linter for AWS Infrastructure

**Status:** Draft v1.1 (revised after review) · **Owner:** Ayushman Nanda · **Date:** 12 Nov 2026
**Working title:** `pqlint` (rename freely; keep the name in one place, `pyproject.toml`)

---

## 1. Summary

`pqlint` is a free, open-source, CI-friendly command-line tool that finds quantum-vulnerable cryptography in AWS infrastructure. **v0.1** focuses on **pre-deployment** scanning of Terraform, fully offline; **v0.2** adds read-only live-account scanning and CloudFormation. For every finding it explains the risk using the Mosca inequality, suggests a fix as a reviewable Terraform diff where AWS supports one, and exports standard formats (CycloneDX CBOM, SARIF) so results plug into existing security tooling.

A static, client-side dashboard is a **stretch goal (v0.3)**, not part of the v0.1.0 release.

## 2. Background and problem

- NIST finalized the first post-quantum standards in 2024 (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA), and governments are pushing migration deadlines closer.
- Migration starts with a **cryptographic inventory**: you cannot replace what you cannot see.
- "Harvest-now, decrypt-later" means data encrypted today with RSA/ECC key exchange may be exposed in the future, so long-lived sensitive data is already at risk.
- Cloud infrastructure is defined in code (Terraform, CloudFormation), yet crypto choices inside it (KMS key specs, certificate algorithms, TLS policies) are rarely reviewed for quantum readiness.

## 3. Market context and gap hypotheses

Commercial and enterprise platforms already offer cryptographic discovery with some AWS support (for example QuantumGenie CipherScan, CBOM Secure, Fortanix Key Insight, SandboxAQ, IBM CBOMkit). Open-source tools exist mostly for **source code**. This project therefore **does not claim to be first**. It targets these hypotheses, each to be validated in Week 1 (see §14):

| # | Gap hypothesis | How pqlint addresses it |
|---|---|---|
| G1 | Cloud-config PQC tooling is mostly enterprise, contract-priced | Free, open-source, runs on a laptop |
| G2 | Most tools inventory existing assets; few check IaC pre-deploy | `scan-iac` mode designed for pull-request CI |
| G3 | Reports are not actionable | Fix suggestions as Terraform diffs, limited to AWS-supported options |
| G4 | Risk labels are generic ("vulnerable") | Per-finding Mosca scoring with configurable assumptions |
| G5 | Little tooling aimed at students, startups, and emerging markets | Zero-cost, zero-signup, offline-capable |

**Success of the project does not depend on competing with enterprise platforms.** It depends on being a credible, useful, well-engineered open-source tool.

## 4. Goals and non-goals

### Goals
1. Detect quantum-vulnerable and weak cryptography in Terraform (v0.1) and CloudFormation (v0.2) for a defined set of AWS resources (§7), fully offline.
2. (v0.2) Optionally inventory the same resource types in a live AWS account using read-only API calls, with account IDs redacted by default.
3. Score each finding with an explainable, configurable Mosca-based model.
4. Generate fix suggestions as Terraform diffs, only where supported (verified data file, see FR-30s).
5. Export CycloneDX 1.6 CBOM, SARIF 2.1.0, JSON, and a human-readable terminal/Markdown report, with sensitive identifiers redacted by default.
6. Ship a GitHub Action and pre-commit hook for CI use.
7. Cost the developer and users **₹0 / $0** to build and run.
8. Never leak AWS account IDs in any exported artifact unless the user explicitly opts out.

### Non-goals (v1)
- Not a runtime traffic interceptor or network scanner of third-party systems.
- Not source-code crypto scanning (existing tools cover this; we may integrate later).
- Not a replacement for commercial inventory platforms.
- Not multi-cloud (Azure/GCP are future work).
- Does not auto-apply changes to infrastructure.
- Does not execute Terraform (or any other external tool) on the user's behalf.
- No telemetry, accounts, or hosted backend.

## 5. Target users and personas

| Persona | Need | Key feature |
|---|---|---|
| **DevSecOps engineer at a startup** | Block quantum-vulnerable crypto from entering IaC | CI Action, SARIF in PR checks |
| **Cloud security consultant / auditor** | Quick PQC readiness snapshot of a client account | Live scan mode (v0.2) + CBOM + report |
| **Student / researcher** | Learn and study PQC migration on real configs | Explainable findings, open data files |
| **Open-source contributor** | Add rules for new resource types | Declarative YAML rule format |

## 6. Hard constraints

- **Free-only:** no paid services, no paid dependencies. Development uses `moto` and local fixtures. A real AWS account is used only for short final validation on the Free plan, with a budget alert set. Do not depend on the 6-month Free plan window.
- **Offline IaC scanning:** `scan-iac` makes **zero network calls** and **never executes `terraform`** or any other external binary. The default input is `.tf` source parsed natively with `python-hcl2`. Optionally, pqlint reads a Terraform **plan JSON file that the user generated themselves**. Generating one can require network access (`terraform init`, providers, remote modules or state), but that happens outside pqlint and is the user's responsibility. Values that cannot be resolved offline are reported as `unknown`.
- **Read-only AWS access (v0.2):** live mode only calls `Describe*`, `List*`, `Get*`. A minimal IAM policy is shipped in the repo.
- **Redaction by default:** AWS account IDs are masked in **every** output format (terminal, Markdown, JSON, SARIF, CBOM) before anything is written to disk or printed. Opting out requires an explicit `--no-redact` flag.
- **Privacy:** no telemetry; no data leaves the user's machine. If the dashboard is built (v0.3), it parses files client-side only.
- **Honesty:** never claim an AWS service supports a PQ option unless it is recorded in the support matrix with a source URL and a verified date.
- **Time and scope:** solo developer, part-time alongside coursework. **v0.1.0 = offline Terraform scanner only.** Live mode and CloudFormation are v0.2; the dashboard is a v0.3 stretch goal.

## 7. Scope: supported resources (v1)

Terraform resource types (v0.1). CloudFormation equivalents and live-mode API sources follow in v0.2.

| Area | Terraform resource | What we check |
|---|---|---|
| KMS | `aws_kms_key` | Key spec: RSA_* / ECC_* (quantum-vulnerable asymmetric) vs SYMMETRIC_DEFAULT; key usage |
| Certificates | `aws_acm_certificate` | `key_algorithm` (RSA_*, EC_*), signature algorithm where available |
| Load balancing | `aws_lb_listener` | `ssl_policy` (TLS versions, key exchange support, PQ policy availability) |
| CDN | `aws_cloudfront_distribution` | Viewer certificate min protocol version / security policy |
| API | `aws_api_gateway_domain_name`, `aws_apigatewayv2_domain_name` | Security policy / TLS version |
| Storage | `aws_s3_bucket_server_side_encryption_configuration` | AES256 vs aws:kms; referenced KMS key spec |
| Database | `aws_db_instance`, `aws_rds_cluster` | `storage_encrypted`, KMS key reference, CA certificate identifier |
| IAM | `aws_iam_server_certificate` | Certificate algorithm (parsed from body when present) |
| Signing | `aws_signer_signing_profile` / KMS signing keys | Signature algorithm class |

Stretch (v1.1+): Secrets Manager, VPN connections (IKE/IPsec params), SES/SQS/SNS TLS settings, EKS.

## 8. Functional requirements

### 8.1 Scanning
| ID | Requirement | Priority |
|---|---|---|
| FR-01 | `pqlint scan-iac <path>` scans a directory of `.tf` files using native `python-hcl2` parsing; this is the default, fully offline path | P0 |
| FR-02 | Same for CloudFormation YAML/JSON templates | P1 (v0.2) |
| FR-03 | `pqlint scan-live --profile <p> --region <r>` inventories supported resource types read-only; subject to all redaction requirements (§8.7) | P2 (v0.2) |
| FR-04 | Resolve simple references (`aws_kms_key.x.arn`) so findings link resources (e.g., S3 → KMS key) | P1 |
| FR-05 | Handle variables with defaults; mark unresolved values as "unknown", never guess | P0 |
| FR-06 | Ignore directives (`# pqlint:ignore RULE_ID reason`) and a config file for suppressions | P1 |
| FR-07 | `scan-iac --plan plan.json` reads a Terraform plan JSON file supplied by the user. pqlint never runs `terraform`, and never fetches modules, providers, or remote state | P1 |
| FR-08 | `scan-iac` makes zero network calls; enforced by a test that blocks sockets during the scan | P0 |

### 8.2 Knowledge base and rules
| ID | Requirement | Priority |
|---|---|---|
| FR-10 | Algorithm knowledge file classifies algorithms: `broken`, `quantum-vulnerable`, `quantum-weakened`, `quantum-safe`, `post-quantum` | P0 |
| FR-11 | Rules are declarative YAML (resource type, attribute, condition, finding text, severity base) | P0 |
| FR-12 | Each rule cites a reference (NIST doc, AWS doc) for traceability | P0 |
| FR-13 | Rule test fixtures: each rule has at least one passing and one failing sample | P0 |

### 8.3 Risk scoring
| ID | Requirement | Priority |
|---|---|---|
| FR-20 | Mosca model: flag risk when `X + Y > Z`, where X = data shelf life, Y = migration time, Z = estimated time to a cryptographically relevant quantum computer | P0 |
| FR-21 | Defaults provided; users override via config (`shelf_life_years`, `migration_years`, `crqc_years`) per resource tag or globally | P0 |
| FR-22 | Distinguish **confidentiality exposure** (key exchange / encryption, harvest-now-decrypt-later) from **authenticity exposure** (signatures, certificates) in scoring and wording | P0 |
| FR-23 | Output score band (Critical/High/Medium/Low/Info) plus a one-line explanation of how it was derived | P0 |
| FR-24 | Document that Z is an assumption, not a prediction, in every report footer | P0 |

### 8.4 Remediation suggestions
| ID | Requirement | Priority |
|---|---|---|
| FR-30 | Ship `data/aws_pq_support.yaml`: per service, which PQ/hybrid options exist, with source URL and `verified_on` date | P0 |
| FR-31 | Suggest a Terraform diff only if the support matrix confirms an option; otherwise state "no AWS-supported migration path currently verified" | P0 |
| FR-32 | Suggestions are output as unified diff text; never applied automatically | P0 |
| FR-33 | CI check that fails if any support-matrix entry is older than a configurable threshold (staleness guard) | P2 |

### 8.5 Outputs
| ID | Requirement | Priority |
|---|---|---|
| FR-40 | Terminal table (default) and Markdown report | P0 |
| FR-41 | JSON (stable, versioned schema) | P0 |
| FR-42 | SARIF 2.1.0 for GitHub code scanning | P0 |
| FR-43 | CycloneDX 1.6 CBOM | P0 |
| FR-44 | Exit codes: 0 clean, 1 findings at/above `--fail-on` severity, 2 tool error | P0 |

### 8.6 Integrations
| ID | Requirement | Priority |
|---|---|---|
| FR-50 | GitHub Action wrapper with PR annotations via SARIF | P1 |
| FR-51 | pre-commit hook definition | P1 |
| FR-52 | **Stretch (v0.3):** static dashboard (Next.js or plain static site, free hosting) that loads JSON/SARIF/CBOM client-side and shows summary, filters, per-resource detail, and diff suggestions | P3 |

### 8.7 Redaction and data safety
Account IDs are identifiers, not credentials, but they appear inside ARNs and help attackers with reconnaissance. SARIF and CBOM files are often uploaded to CI platforms or shared publicly, so redaction is a default behavior.

| ID | Requirement | Priority |
|---|---|---|
| FR-60 | A single redaction layer sits between the findings model and **all** reporters; no output path may bypass it | P0 |
| FR-61 | Redact structurally: mask the account field of ARNs and known account-ID attributes (e.g., owner or account ID fields), plus a conservative fallback for 12-digit numbers in ARN-like or ID-like contexts. Do **not** blindly mask every 12-digit number | P0 |
| FR-62 | Replace each distinct account ID with a stable placeholder (`ACCT-1`, `ACCT-2`, ...) assigned deterministically, so findings across accounts remain distinguishable. The real-to-placeholder mapping is never written to any output | P0 |
| FR-63 | Apply the same redaction to free-text fields (resource names, tags, messages, source locations) | P1 |
| FR-64 | `--no-redact` is an explicit opt-out and prints a warning that outputs may contain account IDs | P1 |
| FR-65 | Leak tests: for every output format, golden tests seed fake account IDs in inputs and assert none appear in the output | P0 |

## 9. Non-functional requirements

- **Cost:** ₹0 to develop, run, and host.
- **Performance:** scan 1,000 Terraform resources in under 10 seconds on a typical laptop.
- **Portability:** Python 3.10+; works on Windows, Linux, macOS (CI tests all three where feasible).
- **Determinism:** same input and config produce identical output ordering.
- **Security:** no network calls in `scan-iac` and no execution of external tools; live mode (v0.2) only calls the AWS API read-only; no credentials logged; account IDs redacted by default; minimal-IAM policy provided.
- **Quality:** ≥85% test coverage on core engine; typed (mypy clean); linted (ruff).
- **Docs:** README quick start in under 5 minutes; rule authoring guide; architecture doc.
- **License:** Apache-2.0 or MIT (decide before first release).

## 10. System design overview

```
            ┌────────────┐   ┌─────────────┐
 .tf / CFN ─►  Parsers    │   │ boto3 live  │◄─ AWS (read-only)
            │ (hcl2/yaml) │   │ collectors  │
            └─────┬──────┘   └──────┬──────┘
                  └──────┬──────────┘
                         ▼
              Normalized Resource Model
                         ▼
        ┌──────────── Rule Engine ◄── rules/*.yaml
        │                 │       ◄── data/algorithms.yaml
        ▼                 ▼
   Mosca Scorer     Fix Suggester ◄── data/aws_pq_support.yaml
        └────────┬────────┘
                 ▼
          Findings Model
                 ▼
   Reporters: table · md · json · SARIF · CBOM
                 ▼
     CLI · GitHub Action · Dashboard (static)
```

Key design decisions:
1. **Normalized resource model** decouples parsers from rules, so IaC and live mode share the same rules.
2. **Rules and knowledge as data (YAML)** so contributors add coverage without touching engine code.
3. **Support matrix as a separate, dated, sourced data file** so fix suggestions can never silently go stale or become fabricated.
4. **Static dashboard (stretch, v0.3), no backend** keeps it free and privacy-preserving.
5. **Redaction at the reporter boundary:** every reporter receives findings through one redaction layer, so no output format can leak identifiers by accident.
6. **Offline by construction:** the parser layer performs no I/O except reading local files the user points to.

## 11. Milestones and release plan

### v0.1.0: offline Terraform scanner (target ~8 weeks, solo, part-time)

| Milestone | Deliverable | Exit criteria |
|---|---|---|
| **M0 — Validation (Week 1)** | Competitive check and gap confirmation (§14); repo skeleton; license; CI | Written findings note; go/no-go on positioning |
| **M1 — Core engine (Weeks 2-3)** | `python-hcl2` parser, normalized model, algorithm KB, 4 rules (KMS, ACM, ALB listener, S3), socket-blocking offline test | `scan-iac` produces table + JSON on fixtures; tests pass; FR-08 test green |
| **M2 — Scoring, outputs, redaction (Week 4)** | Mosca scorer, SARIF, CBOM, exit codes, **redaction layer + leak tests** | CBOM validates against CycloneDX 1.6 schema; SARIF loads in GitHub; FR-65 leak tests green for every format |
| **M3 — Remediation (Week 5)** | Support matrix with verified sources, diff suggester | Every suggestion traceable to a dated source |
| **M4 — CI integration and remaining rules (Week 6)** | GitHub Action, pre-commit hook, remaining v1 rules (CloudFront, API Gateway, RDS, IAM certificate), optional `--plan` input | Example repo shows PR annotation from SARIF |
| **M5 — Hardening (Week 7)** | False-positive audit on public example repos, docs, rule authoring guide | `docs/validation.md` written; README quick start works |
| **M6 — Release (Week 8)** | v0.1.0 on PyPI, demo GIF, announcement post | README quick start verified by someone else |

**Slip policy:** if the schedule slips, cut rules or the `--plan` input first. Never cut tests, redaction, or the support-matrix sourcing.

### v0.2: live mode and CloudFormation
- `scan-live` (read-only) with `moto`-based tests, minimal IAM policy, and full redaction coverage
- CloudFormation parser parity

### v0.3 (stretch): dashboard and extras
- Static client-side dashboard
- Extra resource types (Secrets Manager, VPN/IKE, SES/SNS/SQS TLS, EKS)
- Write-up or short paper

## 12. Success metrics

- **Product:** detects all seeded vulnerabilities in the fixture suite with zero false negatives; false-positive rate under 10% on a set of public example Terraform repos (manually audited).
- **Quality:** coverage and type-check gates green in CI.
- **Adoption (soft targets):** v0.1.0 published; usable by one external person from the README alone; ≥1 external issue or PR; ≥25 GitHub stars is a bonus, not a goal.
- **Learning/portfolio:** architecture doc, rule guide, and a blog post explaining the Mosca model on real cloud configs.

## 13. Risks and mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| An existing OSS tool already covers IaC PQC linting | Medium | M0 check; if so, contribute or differentiate (scoring, fixes, AWS depth) |
| AWS PQ support changes quickly, making suggestions stale | High | Dated, sourced support matrix; staleness CI check; wording "as of verified date" |
| Terraform parsing edge cases (modules, dynamic blocks, variables) | High | Treat unresolved values as "unknown"; document limits; optional user-supplied plan JSON |
| Plan generation needs network access, conflicting with the offline rule | Resolved | pqlint never runs Terraform; it only reads local files; HCL parsing is the default (FR-01, FR-07, FR-08) |
| Account IDs leak through SARIF/CBOM uploaded to CI | High if unmitigated | Default redaction layer, structural matching, stable placeholders, leak tests for every format (§8.7) |
| Redaction false positives or misses | Medium | Structural matching first, conservative fallback, golden tests with seeded IDs |
| Mosca inputs are subjective, so scores may be criticized | Medium | Make assumptions explicit and configurable; never present as prediction |
| Timeline: solo student, 8 weeks | High | v0.1.0 limited to offline IaC scanner; live mode, CloudFormation and dashboard deferred; slip policy in §11 |
| Scope creep | High | Strict v1 resource list; stretch items only after M6 |
| AWS free plan expiry or ineligibility (prior account) | Low for v0.1 | v0.1 needs no AWS account; v0.2 develops on `moto` with minimal real AWS validation |
| Time lost to exams/coursework | Medium | Milestones are independently shippable |

## 14. Week-1 validation checklist (M0)

1. Search GitHub, PyPI, and npm for open-source tools doing IaC-level PQC/crypto linting (terms: "post-quantum", "CBOM", "terraform", "tfsec", "checkov", "crypto inventory").
2. Check whether Checkov/tfsec/Trivy/KICS already have custom policies for KMS key spec or TLS policy that overlap.
3. Read the current AWS documentation on post-quantum TLS and KMS/ACM support; record sources and dates into the support matrix draft.
4. Decide positioning in two sentences and record it in the decision log.
5. Go/no-go: if the gap is closed by an existing tool, choose between contributing upstream and differentiating (scoring + fixes + AWS depth).

## 15. Open questions

1. License: Apache-2.0 (patent grant) vs MIT (simplicity)?
2. Default Mosca assumptions (X, Y, Z): which sources to cite for the defaults?
3. ~~Plan JSON first or HCL first?~~ **Resolved:** native HCL parsing is the offline default; plan JSON is an optional, user-supplied input.
4. Dashboard stack (Next.js vs minimal static page): **deferred** until v0.3 is actually started.
5. How to treat symmetric encryption (AES-128 vs AES-256) in scoring: informational vs medium?
6. Naming and branding.
7. Exact redaction patterns: which attributes and contexts count as account-ID fields in each resource type?

## 16. Glossary

- **PQC:** Post-quantum cryptography, algorithms believed secure against quantum attacks.
- **CRQC:** Cryptographically relevant quantum computer.
- **HNDL:** Harvest-now-decrypt-later.
- **Mosca inequality:** If X + Y > Z, you are at risk (X = shelf life, Y = migration time, Z = time until a CRQC exists).
- **CBOM:** Cryptographic Bill of Materials (CycloneDX 1.6 supports it).
- **SARIF:** Static Analysis Results Interchange Format.
- **ML-KEM / ML-DSA / SLH-DSA:** NIST FIPS 203 / 204 / 205 algorithms.

## 17. Revision history

- **v1.1 (12 Nov 2026):** After review: (1) native HCL parsing is the offline default and pqlint never runs Terraform; plan JSON is optional and user-supplied; (2) added mandatory account-ID redaction (§8.7); (3) v0.1.0 narrowed to the offline Terraform scanner, with live mode and CloudFormation in v0.2 and the dashboard a v0.3 stretch goal; milestones and risks updated.
- **v1.0 (11 Nov 2026):** Initial draft.
