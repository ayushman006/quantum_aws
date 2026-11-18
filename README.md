# pqlint

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Coverage](https://img.shields.io/badge/coverage-83%25-green.svg)]()
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

> **A high-security, completely offline Terraform linter for AWS Post-Quantum readiness.**

`pqlint` statically analyzes your AWS infrastructure-as-code for quantum-vulnerable cryptography. It operates strictly offline, evaluates risk mathematically using the Mosca inequality, and guarantees zero exposure of your private AWS identifiers through a deterministic redaction engine.

## 🛡️ The Security Guarantee

Security scanners should not become supply-chain risks. `pqlint` is designed with strict data invariants:
* **Zero Network Egress:** The core engine and AST parser make zero socket connections.
* **Fail-Closed Redaction Layer:** Before any data is written to `stdout` or disk, a strict redaction layer intercepts the output. All 12-digit AWS Account IDs and ARNs are structurally masked (e.g., `123456789012` $\rightarrow$ `<REDACTED_ACCOUNT_1>`). A final leak-guard verifies the serialized output; if a raw ID slips through, the tool violently crashes rather than leaking data.

## 📦 Installation

*(Pending PyPI release)*. For now, install directly from the source repository:

```bash
git clone [https://github.com/ayushman006/quantum_aws.git](https://github.com/ayushman006/quantum_aws.git)
cd quantum_aws
pip install -e .