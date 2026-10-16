# Spec It Safe (SIS)

A TypeScript library and CLI that automatically hardens software requirements with security constraints derived from CWE, OWASP, and CVE mappings. It analyzes EARS-format requirements, detects which CWEs are relevant based on keyword and semantic pattern matching, and proposes security requirements to close the gaps — all before a single line of code is written.

## Why

Security vulnerabilities are cheapest to fix at the requirements phase. Yet most teams bolt security on during code review or penetration testing — after the architecture is set. SIS makes security a first-class construct in your specification by:

1. Scanning each requirement for security-relevant patterns (database queries, file uploads, authentication flows, etc.)
2. Mapping those patterns to specific CWEs (e.g., CWE-89 SQL Injection, CWE-862 Missing Authorization)
3. Generating EARS-format security requirements with rationale, priority, and traceability

## Installation

`@sis/cwe-to-spec-mapping` is not published to a registry. Build it from source in this workspace:

```bash
cd src/KiroSecureSpecHardening/cwe-to-spec-mapping-library
npm install   # installs devDependencies and runs the build via `prepare`
```

To consume it from another local project, install it by path:

```bash
npm install /path/to/KiroSecureSpecHardening/src/KiroSecureSpecHardening/cwe-to-spec-mapping-library
```

## Quick Start

All commands must be run from the package directory:

```bash
cd src/KiroSecureSpecHardening/cwe-to-spec-mapping-library
```

### CLI Usage

```bash
# Harden a single requirements file (compiled CLI, built by `npm install`)
node dist/cli/harden-requirements.js /abs/path/to/requirements.md

# Harden all markdown files in a directory
node dist/cli/harden-requirements.js /abs/path/to/project/.kiro/specs/

# With options
node dist/cli/harden-requirements.js /abs/path/to/requirements.md --threshold 0.5 --no-low-severity

# Print sub-threshold authorization gaps for semantic review
node dist/cli/harden-requirements.js /abs/path/to/project/.kiro/specs/ --semantic-candidates

# Fallback: from source, no build step (needs the tsx devDependency)
npm run harden -- /abs/path/to/project/.kiro/specs/
```

To get a global `harden-requirements` command, run `npm link` once in this
directory.

The CLI hardens each input file **in place** — no sidecar files. It:

- normalizes each requirement line to strict EARS,
- nests **requirement-specific** constraints as sub-numbered EARS items under the
  requirement they harden — each written in the parent's own subject (e.g. `THE
  Cron_SDK SHALL`, not the canonical `THE SYSTEM SHALL`) so the constraint reads
  in the spec's voice and stays traceable to the component it guards, and
- consolidates **cross-cutting** constraints (those a clause would otherwise
  repeat under most requirements — parameterized queries, authentication, generic
  input validation) into a single `## Security Baseline (Cross-Cutting)` section
  at the end, stated once.

Any `*_hardened.md` or `*final_requirements.md` left by an older two-file run is
removed. Strip the `[SECURITY: ...]` lines and the baseline section and you get
the original file back, so it is easy to see what hardening changed — or just
diff against version control.

```markdown
1. WHEN a user submits a search query, THE SYSTEM SHALL return matching results from the database.
   1.1. SEC-…-EC-89-2-1 [SECURITY: input-validation] WHEN a user submits a search query, THE SYSTEM SHALL sanitize all input parameters against an allowlisted character set.
2. THE SYSTEM SHALL accept images up to 5MB in size.

## Security Baseline (Cross-Cutting)

- SEC-BASELINE-1 [SECURITY: parameterized-query] THE SYSTEM SHALL execute all database queries using parameterized statements or prepared statements only.
- SEC-BASELINE-2 [SECURITY: authentication-required] WHILE any request to this endpoint is being processed, THE SYSTEM SHALL require a valid authenticated session or signed token.
```

Here requirement 1 picked up a contextual input-validation clause while the
parameterized-query and authentication constraints — which applied to nearly
every requirement — were lifted to the baseline. Re-running the CLI on an
already-hardened file is a **no-op**: it detects the `[SECURITY: ...]` tags and
leaves the file untouched, since the EARS-split output does not round-trip back
through the parser. To harden requirements added after a hardening pass, run
against the pre-hardening spec (e.g. from version control). See
[`examples/user-management.hardened.md`](examples/user-management.hardened.md)
for a full worked output.

### Programmatic Usage

```typescript
import { HardeningEngine, formatAsSecurityAnnotatedEARS } from "@sis/cwe-to-spec-mapping";

const engine = new HardeningEngine();

const report = engine.harden([
  {
    id: "REQ-1",
    text: "WHEN a user submits a search query, THE SYSTEM SHALL return matching results from the database.",
    earsPattern: "event-driven",
  },
]);

// Get formatted output
const hardened = formatAsSecurityAnnotatedEARS(report);
console.log(hardened);

// Or inspect the structured report
console.log(report.summary);
// {
//   totalRequirements: 1,
//   requirementsWithGaps: 1,
//   totalCWEsTriggered: 3,
//   totalProposedAdditions: 5,
//   criticalGaps: 5,
//   overallSecurityScore: 0.0
// }
```

## How It Works

```
Requirements (EARS format)
        │
        ▼
┌─────────────────────┐
│  Trigger Detector   │  ← matches keywords + semantic patterns against CWE trigger conditions
└─────────────────────┘
        │
        ▼
┌─────────────────────┐
│  Coverage Checker   │  ← identifies which security primitives are missing
└─────────────────────┘
        │
        ▼
┌─────────────────────┐
│  Hardening Engine   │  ← generates contextualized EARS security requirements
└─────────────────────┘
        │
        ▼
Hardened Specification (with CWE traceability)
```

### Trigger Detection

Each CWE mapping has trigger conditions defined by:
- **Keywords** — terms like "database", "upload", "session", "password"
- **Semantic patterns** — regex patterns like `"user submits.*search"`, `"store.*credentials"`
- **Data flow indicators** — paths like `"user input → database query"`

When a requirement matches trigger conditions above a confidence threshold, the corresponding CWE is flagged.

### Coverage Analysis

Once relevant CWEs are identified, the engine checks whether existing requirements already cover the needed security primitives (e.g., parameterized queries, output encoding, CSRF tokens). Only uncovered gaps produce proposals.

### Proposal Generation

Proposals are contextualized using the original requirement's actors, operations, and resources. Each proposal includes:
- EARS-format requirement text
- Which CWE(s) it addresses
- The security primitive it enforces
- Priority (mandatory / recommended / optional based on severity)
- Rationale explaining why

## CWE Coverage

The library includes 60 CWE mappings across 8 security domains:

| Domain | Example CWEs |
|--------|-------------|
| Injection | CWE-89 (SQLi), CWE-78 (OS Command), CWE-79 (XSS), CWE-94 (Code Injection), CWE-90 (LDAP), CWE-643 (XPath), CWE-113 (HTTP Response Splitting), CWE-98 (File Inclusion), CWE-470 (Unsafe Reflection) |
| Authentication | CWE-306 (Missing Auth), CWE-307 (Brute Force), CWE-384 (Session Fixation) |
| Authorization | CWE-862 (Missing Authz), CWE-639 (IDOR), CWE-285 (Improper Authz) |
| Data Exposure | CWE-200 (Info Exposure), CWE-209 (Error Messages), CWE-532 (Log Injection) |
| Cryptography | CWE-326 (Weak Encryption), CWE-327 (Broken Crypto), CWE-522 (Weak Credentials), CWE-295 (Certificate Validation), CWE-347 (Signature Verification) |
| Input Validation | CWE-20 (Improper Validation), CWE-434 (File Upload), CWE-352 (CSRF), CWE-807 (Untrusted Input in Security Decision) |
| Security Misconfiguration | CWE-16 (Configuration), CWE-1004 (Cookie Flags), CWE-942 (CORS), CWE-732 (Loose Permissions), CWE-377 (Insecure Temp File), CWE-489 (Active Debug Code) |
| Business Logic | CWE-362 (Race Conditions), CWE-770 (Resource Exhaustion), CWE-208 (Timing), CWE-1333 (ReDoS), CWE-409 (Zip Bomb) |

### Sources

Mappings are curated from the [OWASP Top 10](https://owasp.org/Top10/), the
[CWE Top 25](https://cwe.mitre.org/top25/), and the security detectors in the
[Amazon CodeGuru Detector Library](https://docs.aws.amazon.com/codeguru/detector-library/).
The CodeGuru-derived additions cover injection variants (LDAP, XPath, CRLF/HTTP
response splitting, file inclusion, unsafe reflection), transport and token trust
(TLS certificate validation, cryptographic signature verification), denial-of-service
by amplification (ReDoS, decompression/zip bombs), filesystem hardening (loose
permissions, insecure temporary files, active debug code), and reliance on
untrusted input in security decisions.

## EARS Pattern Support

The library understands all standard EARS (Easy Approach to Requirements Syntax) patterns:

- **Ubiquitous** — `THE SYSTEM SHALL...`
- **Event-driven** — `WHEN <event>, THE SYSTEM SHALL...`
- **State-driven** — `WHILE/IF <state>, THE SYSTEM SHALL...`
- **Optional feature** — `WHERE <feature>, THE SYSTEM SHALL...`
- **Unwanted behavior** — `THE SYSTEM SHALL NOT...`
- **Complex** — combinations of the above

## CLI Options

```
Usage: harden-requirements <file.md|directory> [file2.md ...]

Options:
  --threshold <n>       Confidence threshold (0-1, default: 0.3)
  --max-proposals <n>   Max proposals per requirement (default: 10)
  --no-low-severity     Exclude low-severity CWEs
  --semantic-candidates Print sub-threshold CWEs for agentic adjudication
                        (printed only, never written to the file). By default
                        only object-level authorization gaps are surfaced.
  --semantic-all        With --semantic-candidates, surface every sub-threshold CWE
  --semantic-floor <n>  Lower bound for surfacing candidates (0-1, default: 0.05)
  -h, --help            Show this help
```

## API Reference

### `HardeningEngine`

```typescript
const engine = new HardeningEngine(mappings?: CWEMapping[]);
const report: HardeningReport = engine.harden(requirements, options?);
```

**Options:**
| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `confidenceThreshold` | number | 0.3 | Minimum confidence to trigger a CWE (0-1) |
| `includeLowSeverity` | boolean | true | Include low-severity CWEs in analysis |
| `maxProposalsPerRequirement` | number | 10 | Cap proposals per requirement |

### `TriggerDetector`

```typescript
const detector = new TriggerDetector(mappings?: CWEMapping[]);
const triggered: TriggeredCWE[] = detector.detectTriggers(requirement);
```

### `CoverageChecker`

```typescript
const checker = new CoverageChecker(mappings?: CWEMapping[]);
const gaps: CoverageGap[] = checker.checkCoverage(requirements, triggeredCWEs);
```

### Mapping Accessors

```typescript
import {
  allMappings,
  getMappingById,
  getMappingsByTag,
  getMappingsByOwasp,
  getMappingsBySeverity,
} from "@sis/cwe-to-spec-mapping/mappings";

const sqli = getMappingById("CWE-89");
const injections = getMappingsByTag("injection");
const critical = getMappingsBySeverity("critical");
```

### Markdown Utilities

```typescript
import { parseRequirementsFromMarkdown, hardenMarkdownFile } from "@sis/cwe-to-spec-mapping";

// Parse EARS requirements from a markdown file
const requirements = parseRequirementsFromMarkdown(markdownContent, filePath);

// Harden a file in place (curated, no sidecar files)
const result = await hardenMarkdownFile("requirements.md", options);
result.outputPath;          // .../requirements.md  (edited in place; === input)
result.baselineConstraints; // count lifted into the Security Baseline section
result.removedArtifacts;    // any stale *_hardened.md / *final_requirements.md removed
```

## Integration with Kiro

SIS is designed to integrate into Kiro's spec-driven development workflow:

```
Specify (EARS) → [SIS Hardening] → Plan → Execute
```

Installed as part of the Spec It Safe power, the `harden-spec` skill runs this
CLI for you. Ask Kiro to *"harden my specs"* and it finds the engine, confirms
which specs to harden, runs the CLI, and does a semantic review pass on top. See
the [power README](../README.md#run-it).

To run it yourself, from the package directory:

```bash
# Using the compiled CLI
node dist/cli/harden-requirements.js /abs/path/to/project/.kiro/specs/ --semantic-candidates

# Or directly from source (no build needed; uses tsx)
npm run harden -- /abs/path/to/project/.kiro/specs/
```

The hardened output preserves all functional requirements while adding security constraints as traceable, testable EARS statements.

## Example

**Input requirement:**
> WHEN a user submits a search query, THE SYSTEM SHALL return matching results from the database.

**Triggered CWEs:** CWE-89 (SQL Injection), CWE-306 (Missing Auth), CWE-20 (Input Validation)

**Proposed security requirements:**

> `[SECURITY: parameterized-query]`
> THE SYSTEM SHALL execute all database queries using parameterized statements or prepared statements only. THE SYSTEM SHALL NOT construct query strings by concatenation of user-supplied values.

> `[SECURITY: input-schema-validation]`
> WHEN external input is received, THE SYSTEM SHALL validate the input against an expected schema (type, length, range, format) and SHALL reject input that does not conform with a descriptive error code.

## Development

All development commands must be run from the package directory (`src/KiroSecureSpecHardening/cwe-to-spec-mapping-library/`):

```bash
# Build
npm run build

# Run tests
npm test

# Watch mode
npm run test:watch

# Harden a file directly from source (uses tsx, no build needed)
npm run harden -- path/to/file.md
```

## License

MIT-0. See the [LICENSE](../LICENSE) file.
