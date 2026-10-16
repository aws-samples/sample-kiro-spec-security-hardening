---
name: "security-primitives-reference"
description: "Reference knowledge for mapping requirements to CWE/OWASP weaknesses and the security primitives that close them. Use to explain why a hardening constraint was proposed, to justify EARS security requirements, or to harden a spec by hand when the SIS engine cannot run."
license: "MIT-0"
metadata:
  author: "Rajdeep Mukherjee"
  version: "1.0.0"
---

# Security Primitives Reference

The knowledge base behind the `harden-spec` skill. Use it to explain a proposal,
justify a constraint, or harden requirements by hand when the engine is
unavailable. The authoritative, machine-readable mappings live in
`cwe-to-spec-mapping-library/src/mappings/` — read those for exact trigger
keywords, semantic patterns, and EARS constraint templates.

## Method: requirement → CWE → primitive → EARS constraint

1. **Detect triggers.** Match the requirement's text against CWE trigger
   conditions: keywords ("database", "upload", "session", "password"), semantic
   patterns (`user submits.*search`, `store.*credentials`), and data-flow
   indicators (`user input → database query`).
2. **Check coverage.** For each triggered CWE, decide whether existing
   requirements already state the needed primitive. Only *uncovered* gaps become
   proposals.
3. **Generate the constraint** as EARS, substituting the requirement's own
   `{actor}`, `{resource}`, `{operation}`. Annotate with `[SECURITY: <primitive>]`,
   the CWE(s) addressed, a priority (`mandatory` | `recommended` | `optional`,
   from CWE severity), and a one-line rationale.
4. **Deduplicate** proposals that enforce the same primitive.

## OWASP Top 10 (2021) → CWE coverage

| OWASP Category | CWEs |
|---|---|
| A01 Broken Access Control | CWE-862, CWE-863, CWE-639, CWE-352, CWE-269, CWE-284 |
| A02 Cryptographic Failures | CWE-330, CWE-327, CWE-326, CWE-916 |
| A03 Injection | CWE-89, CWE-78, CWE-79, CWE-94, CWE-917 |
| A04 Insecure Design | CWE-362, CWE-770, CWE-841, CWE-799, CWE-434, CWE-400 |
| A05 Security Misconfiguration | CWE-611, CWE-16, CWE-942, CWE-1021, CWE-269 |
| A06 Vulnerable Components | CWE-1104 |
| A07 Auth Failures | CWE-306, CWE-307, CWE-208, CWE-522, CWE-613, CWE-384, CWE-798 |
| A08 Data Integrity Failures | CWE-345, CWE-502 |
| A09 Logging Failures | CWE-532 |
| A10 SSRF | CWE-918 |

Plus business-logic / data-exposure: CWE-1236, CWE-346, CWE-22, CWE-601,
CWE-200, CWE-201, CWE-359, CWE-209, CWE-319.

## Common primitives by domain

- **Injection** — parameterized/prepared statements only (no string concatenation
  of user input); allowlist input validation; context-aware output encoding.
- **Authentication** — authenticated session/signed token required before
  processing; rate limiting / lockout against brute force; session rotation on
  privilege change; no hardcoded credentials.
- **Authorization** — ownership/tenancy verification per object (defeats IDOR/BOLA);
  server-side authorization check on every protected operation.
- **Data exposure** — generic error messages to clients; no secrets/PII in logs;
  TLS in transit; least-data-returned.
- **Cryptography** — strong, current algorithms; CSPRNG for tokens; salted
  adaptive password hashing.
- **Input validation** — schema validation (type, length, range, format) with
  descriptive rejection; file-type/size/content validation on upload; CSRF tokens
  on state-changing requests.
- **Business logic** — concurrency/race protection; resource-consumption limits;
  constant-time comparison for secrets.

## EARS patterns for constraints

- Ubiquitous: `THE SYSTEM SHALL …`
- Event-driven: `WHEN <event>, THE SYSTEM SHALL …`
- State-driven: `WHILE <state>, THE SYSTEM SHALL …`
- Unwanted behavior: `IF <condition>, THE SYSTEM SHALL …` / `THE SYSTEM SHALL NOT …`

## Worked example

Requirement:
> WHEN a physician searches for clinical notes by patient name, THE SYSTEM SHALL return all matching clinical notes from the records database.

Triggered: CWE-89 (SQLi), CWE-862 (missing authz), CWE-306 (missing auth).

Proposed hardening:

```
[SECURITY: parameterized-query]  (CWE-89, mandatory)
THE SYSTEM SHALL execute all database queries using parameterized statements only.
THE SYSTEM SHALL NOT construct query strings by concatenation of user-supplied values.
Rationale: separates SQL logic from data, making injection structurally impossible.

[SECURITY: ownership-verification]  (CWE-862, mandatory)
THE SYSTEM SHALL verify the requesting physician is an assigned care provider for
the patient before returning clinical notes.
Rationale: BOLA/IDOR arises when object access lacks ownership checks.

[SECURITY: authentication-required]  (CWE-306, mandatory)
THE SYSTEM SHALL require a valid authenticated session or signed token before
processing the request.
Rationale: every endpoint serving non-public data must verify caller identity.
```
