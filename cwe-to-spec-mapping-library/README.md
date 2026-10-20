# Spec It Safe (SIS)

A TypeScript library and CLI that automatically hardens software requirements with security constraints derived from CWE, OWASP, and CVE mappings. It analyzes EARS-format requirements, detects which CWEs are relevant based on keyword and semantic pattern matching, and proposes security requirements to close the gaps — all before a single line of code is written.

## Why

Security vulnerabilities are cheapest to fix at the requirements phase. Yet most teams bolt security on during code review or penetration testing — after the architecture is set. SIS makes security a first-class construct in your specification by:

1. Scanning each requirement for security-relevant patterns (database queries, file uploads, authentication flows, etc.)
2. Mapping those patterns to specific CWEs (e.g., CWE-89 SQL Injection, CWE-862 Missing Authorization)
3. Generating EARS-format security requirements with rationale, priority, and traceability

## Installation

`@sis/cwe-to-spec-mapping` is not published to a registry. It ships prebuilt in
`dist/` with no runtime dependencies, so the CLI runs with Node.js alone. To
rebuild after changing the source (and before committing):

```bash
npm ci --ignore-scripts && npm run build
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
# Harden a single requirements file (prebuilt compiled CLI)
node dist/cli/harden-requirements.js /abs/path/to/requirements.md

# Harden all markdown files in a directory
node dist/cli/harden-requirements.js /abs/path/to/project/.kiro/specs/

# With options
node dist/cli/harden-requirements.js /abs/path/to/requirements.md --threshold 0.5 --no-low-severity

# Print sub-threshold authorization gaps for semantic review
node dist/cli/harden-requirements.js /abs/path/to/project/.kiro/specs/ --semantic-candidates

# Preview what would be added without writing anything
node dist/cli/harden-requirements.js /abs/path/to/requirements.md --dry-run

# Validate requirements and [SECURITY: ...] lines only (exit 1 on problems)
node dist/cli/harden-requirements.js /abs/path/to/requirements.md --check

# Fallback: from source, no build step (needs the tsx devDependency)
npm run harden -- /abs/path/to/project/.kiro/specs/
```

To get a global `harden-requirements` command, run `npm link` once in this
directory.

The CLI hardens each input file **in place**, and only by adding lines — no
copies, no sidecar files. Every original line, requirement lines included,
stays exactly as written; the CLI refuses to write if one would not. It:

- inserts **requirement-specific** constraints as sub-numbered EARS items under
  the requirement they harden — each written in the parent's own subject (e.g.
  `THE Cron_SDK SHALL`, not the canonical `THE SYSTEM SHALL`) so the constraint
  reads in the spec's voice and stays traceable to the component it guards,
- consolidates **cross-cutting** constraints (those a clause would otherwise
  repeat under most requirements) into a single
  `## Security Baseline (Cross-Cutting)` section at the end, stated once,
- records the requirements it hardened in a hidden
  `<!-- spec-it-safe:reviewed … -->` comment at the end of the file, and
- prints every line it added, by the original line it follows.

```markdown
1. WHEN a user submits a search query, THE SYSTEM SHALL return matching results from the database.
   1.1. SEC-REQ-1.1-EC-89-2-1 [SECURITY: input-validation] WHEN a user submits a search query, THE SYSTEM SHALL validate each input parameter against the format rules defined for its field.
2. THE SYSTEM SHALL accept images up to 5MB in size.

## Security Baseline (Cross-Cutting)

- SEC-BASELINE-1 [SECURITY: parameterized-query] THE SYSTEM SHALL execute all database queries using parameterized statements or prepared statements only.
```

Constraint IDs name the requirement they harden: `SEC-REQ-1.1-…` is criterion 1
of "Requirement 1". A requirement with its own ID (`REQ-F-015: …`) keeps it
(`SEC-REQ-F-015-…`). Warnings name requirements the same way, with the line
number.

**Context.** Constraints are chosen against the whole document, not one
requirement at a time. A mapping that needs a SQL database, HTTP, a browser,
XML or LDAP is withheld when the spec shows no sign of one, and a constraint is
withheld when the spec declares its topic out of scope ("TLS is out of
scope"). Withheld constraints are listed as `[INFO]`. Keywords and patterns
match whole words, so "logout" is not "log" and "invalid" is not "id".

**Wording.** A template is resolved for the spec before it is filled
(`resolveTemplate`, `fillTemplate`). Its default wording is
technology-neutral; a `variants` entry supplies the wording for specs that
have a feature (`http`, `sql-database`, …). An `{<concept>_examples}` slot
names the APIs of the languages the spec states (`detectSpecContext` finds Go,
Java, Python, JavaScript/TypeScript, .NET, Ruby and PHP), with a cross-language
default otherwise. A trailing "before …" moves into a leading trigger only when
it names an event ("before executing the operation", "before the token
expires"). A bare noun ("before use") stays in the response, and a one-word
trigger such as `WHEN use,` is rejected. Placeholders the requirement cannot
fill fall back to generic text and are reported (`genericSlots` on the
proposal, `[WARN] … built with generic text` in the CLI). The semantic-review
list shows candidates filled in the same way, in the requirement's own
subject.

**Placement.** Within one "Requirement N" section, a clause proposed under
several criteria is written once, under the first (`foldedDuplicates`).
Baseline constraints use the subject the existing baseline already uses,
else a requirement subject named as the system (`Chat_System`), else the one
subject all requirements share, else `THE SYSTEM`.

**Constraint checks.** Every `[SECURITY: ...]` line in the file — generated or
hand-written — is validated on each run (`constraintWarnings`). The checks
are: one obligation per line, a named actor, a well-formed trigger, and an ID
starting `SEC-` that no other line uses. `--check` runs this and the source
EARS check alone, writes nothing, and exits 1 if anything is reported.
Hand-added constraints should use `SEC-<requirement>-SEM-<CWE>-<n>` IDs.

**Warnings.** `[WARN] … not strict EARS` names a requirement that does not
follow EARS; it is reported, never rewritten. Any named component counts as the
actor (`THE Chat_Server SHALL`), not only `THE SYSTEM`.

The EARS check is structural only. It verifies the trigger keywords and their
closing commas, `IF … THEN`, a named actor and a `SHALL`, but not whether the
response is complete. A truncated statement such as `THE Chat_Server SHALL
create.` (or even `THE Chat_Server SHALL.`) passes without a warning. No
warning means the requirement is well-formed EARS, not that it says everything
it should, so read each requirement for completeness yourself. Hardening never
produces such a statement, because it never splits or rewrites a requirement.

`[WARN] … only on the keywords` flags constraints whose CWE matched on keywords alone, which are the
ones most likely to be attached to the wrong requirement.

**Re-runs** are incremental. Only requirements added or changed since the last
run are hardened. Constraints a reviewer deleted are not proposed again for
requirements already reviewed, and a clause already stated anywhere in the
file is not added twice. A file with nothing new is left byte-identical. A file
hardened by an older version (tags but no review comment) is skipped; run it
once with `--mark-reviewed` to record its current requirements. See
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

// Harden a file in place (additive only, no sidecar files)
const result = await hardenMarkdownFile("requirements.md", { dryRun: false });
result.outputPath;            // .../requirements.md  (edited in place; === input)
result.mode;                  // "full" | "incremental" | "up-to-date" | "unrecorded" | "marked"
result.addedLines;            // every added line, with the original line it follows
result.baselineConstraints;   // count added to the Security Baseline section
result.suppressedConstraints; // constraints withheld by spec context, with reasons
result.specializationWarnings; // added constraints built from generic placeholder text
result.constraintWarnings;    // malformed [SECURITY: ...] lines already in the file
result.foldedDuplicates;      // clauses not repeated within one requirement section
result.removedArtifacts;      // any stale *_hardened.md / *final_requirements.md removed
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
