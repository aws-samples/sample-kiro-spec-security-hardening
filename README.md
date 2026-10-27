# Specification Hardening Engine — Kiro Power

Harden your Kiro specs with security primitives **before** code is written.

Specification Hardening Engine analyzes EARS-format requirements, detects which
CWE/OWASP weaknesses each requirement is exposed to, and proposes traceable,
testable security requirements to close the gaps. Security becomes a first-class
construct in the spec — not an afterthought bolted on at code review.

```
Specify (EARS)  →  [ Specification Hardening Engine ]  →  Plan  →  Execute
```

## What's in this power

This repository **is** the power, packaged to the [Agent Plugins v1.0.0](https://agent-plugins.org)
specification so Kiro can install it directly.

```
plugin.json                       # power manifest
skills/
  harden-spec/                    # workflow: run the Specification Hardening Engine over .kiro/specs and apply the results
  security-primitives-reference/  # CWE→primitive knowledge base + methodology
cwe-to-spec-mapping-library/      # the bundled Specification Hardening Engine (TypeScript CLI + library)
```

Two skills are exposed to the Kiro agent:

- **harden-spec** — locates your `.kiro/specs/*/requirements.md`, runs the
  bundled engine, and walks you through the proposed security constraints and
  warnings, then applies them on confirmation.
- **security-primitives-reference** — the CWE/OWASP knowledge base the agent
  uses to explain and justify each constraint, or to harden by hand.

## Prerequisites

- [Kiro IDE](https://kiro.dev) or [Kiro CLI](https://kiro.dev/docs/cli/)
- Node.js 20 or later, and npm
- Git

## Install

### Kiro IDE

Install it as a power. See [Install powers](https://kiro.dev/docs/powers/installation/)
for the full guide.

**From GitHub:**

1. Open the **Powers** panel (the Ghosty icon with the lightning bolt).
2. Click **Add Custom Power**, then **Import power from GitHub**.
3. Enter `https://github.com/aws-samples/sample-kiro-spec-security-hardening`
   and click **Install**.

**From a local folder:**

1. Clone the repository:

   ```bash
   git clone https://github.com/aws-samples/sample-kiro-spec-security-hardening.git specification-hardening-engine
   ```

2. Open the **Powers** panel, click **Add Custom Power**, then
   **Import power from a folder**.
3. Choose the `specification-hardening-engine` directory (it contains `plugin.json`) and click
   **Install**.

**From the Kiro powers registry** (once published): browse
[kiro.dev/powers](https://kiro.dev/powers), select **Specification Hardening Engine**, and click
**Add to Kiro**.

### Kiro CLI

[Kiro CLI](https://kiro.dev/docs/cli/) loads [skills](https://kiro.dev/docs/skills/)
from a project's `.kiro/skills/` directory. Install the two skills there and
clone the engine inside the project, where the `harden-spec` skill can find it:

```bash
cd /path/to/your/project
git clone https://github.com/aws-samples/sample-kiro-spec-security-hardening.git .kiro/specification-hardening-engine
mkdir -p .kiro/skills
cp -R .kiro/specification-hardening-engine/skills/harden-spec .kiro/specification-hardening-engine/skills/security-primitives-reference .kiro/skills/
```

### The engine is prebuilt

The bundled engine ships compiled in `cwe-to-spec-mapping-library/dist/` and
has no runtime dependencies, so an installed power runs with Node.js alone.
To rebuild it after changing the source (contributors only):

```bash
cd specification-hardening-engine/cwe-to-spec-mapping-library   # or .kiro/specification-hardening-engine/... for Kiro CLI
npm ci --ignore-scripts && npm run build
```

Commit the rebuilt `dist/` together with the source change.

## Quick start: try it on the bundled example

The repository ships a sample spec, `examples/user-management.md`, and its
expected hardened output, `examples/user-management.hardened.md`. To see the Specification Hardening Engine
work without writing a spec of your own:

```bash
cd specification-hardening-engine/cwe-to-spec-mapping-library

# The CLI hardens files in place, so work on a copy of the example.
# Keep the file name: constraint IDs are derived from it.
mkdir -p /tmp/spec-hardening-demo
cp examples/user-management.md /tmp/spec-hardening-demo/
node dist/cli/harden-requirements.js /tmp/spec-hardening-demo/user-management.md --semantic-candidates

# Compare with the expected result (no output means identical)
diff /tmp/spec-hardening-demo/user-management.md examples/user-management.hardened.md
```

To try it in Kiro, copy the example into a project as a spec, then ask Kiro to
*Harden my specs* (see [Run it](#run-it)):

```bash
mkdir -p /path/to/your/project/.kiro/specs/user-management
cp examples/user-management.md /path/to/your/project/.kiro/specs/user-management/requirements.md
```

## Run it

### In Kiro IDE

Open your project. Once your functional requirements are finalized, ask Kiro
in the chat panel:

> *Harden my specs* · *Security-review the `checkout` spec* · *Harden `.kiro/specs/payments/requirements.md`*

### In Kiro CLI

Start a chat session from the project root and use the same prompts, or call
the skill directly as a slash command:

```bash
cd /path/to/your/project
kiro-cli
```

```text
> Harden my specs
> /harden-spec .kiro/specs/payments/requirements.md
```

### What the skill does

In either client, the `harden-spec` skill:

1. **Finds the engine** in the installed power by its absolute path.
2. **Lists your specs and confirms once.** "Harden my specs" counts as consent
   to harden every `.kiro/specs/*/requirements.md`. Kiro only asks, in one
   question that lists the specs it found, when it's unclear which spec you mean.
3. **Runs the compiled CLI** with `--semantic-candidates`, then does a semantic
   review pass for missing authorization checks that keyword matching can't see,
   adding domain-specific constraints by hand and curating generated ones that
   don't fit the system. It never edits requirement lines and never copies the
   spec.
4. **Summarizes** the requirements it hardened, the mandatory constraints grouped
   by CWE, the gaps it added in the semantic pass, and any warnings that need you
   to act.

The CLI prints every line it adds, so the changes can be reviewed even when
`.kiro/` is not under version control. `git diff` works too when it is.

### Standalone engine, without Kiro

Build once, then point the compiled CLI at one spec file or a whole specs
directory (directories are searched for `.md` files):

```bash
cd specification-hardening-engine/cwe-to-spec-mapping-library

# Harden every spec in a project
node dist/cli/harden-requirements.js /abs/path/to/project/.kiro/specs/

# Or one spec file
node dist/cli/harden-requirements.js /abs/path/to/project/.kiro/specs/my-feature/requirements.md
```

| Flag | Effect |
|---|---|
| `--semantic-candidates` | Also print sub-threshold matches (mainly object-level authorization gaps) for manual or agent review. Printed only — never written to the file |
| `--semantic-all` | With `--semantic-candidates`, list every sub-threshold CWE, not just authorization gaps (noisier) |
| `--semantic-floor <0-1>` | Lowest score a sub-threshold match needs to be listed (default 0.05) |
| `--threshold <0-1>` | Confidence a match needs before it fires (default 0.3) |
| `--max-proposals <n>` | Most constraints added per requirement (default 10) |
| `--no-low-severity` | Leave out low-severity CWEs |
| `--dry-run` | Print the lines that would be added; write nothing |
| `--check` | Validate only, write nothing: report requirements that are not strict EARS and malformed `[SECURITY: …]` lines (two obligations on one line, no actor, missing or duplicate ID). Exits 1 if anything is reported |
| `--mark-reviewed` | Record the current requirements as reviewed without adding constraints. Use once on a file hardened by an older version, so later runs harden only what is added afterwards |
| `-h`, `--help` | Show full usage |

Other ways to run it:

- **From source, no build:** `npm run harden -- <path> [flags]`. This needs the
  `tsx` devDependency. If you see `tsx: command not found`, run
  `npm install --include=dev`.
- **As a global command:** run `npm link` once in
  `cwe-to-spec-mapping-library/`, then call `harden-requirements <path> [flags]`
  from anywhere.

### What it changes

It hardens each `filename.md` **in place**, and only by adding lines. Every
original line stays exactly as written: requirements are never split,
re-tagged, reworded or moved. Requirement-specific `[SECURITY: …]` constraints
are inserted under the requirement they harden, cross-cutting constraints are
consolidated into one `## Security Baseline (Cross-Cutting)` section, and a
hidden `<!-- spec-it-safe:reviewed … -->` comment at the end records which
requirements were hardened. The CLI refuses to write if any original line
would not survive unchanged. No copies or sidecar files are written.

Constraints are chosen in the context of the whole document. A spec with no
SQL database gets no SQL-injection constraints, a spec with no browser gets no
CSP or CSRF constraints, and a topic the spec declares out of scope (for
example "TLS is out of scope") gets no constraint that contradicts that
decision. Withheld constraints are listed in the output. Constraints whose CWE
matched only on loose keywords are flagged for review as possibly misplaced.

Requirements that are not strict EARS are reported, never rewritten. The check
is structural: it confirms the EARS keywords, a named actor such as
`THE Chat_Server` and a `SHALL`, but not that the response is complete. A
truncated requirement such as `THE Chat_Server SHALL create.` passes without a
warning, so the absence of warnings is not a completeness review.

Wording follows the spec, too. Templates have neutral defaults, and
technology-specific variants are used only when the spec has that technology
(e.g. "web-accessible document root" only for a web spec). Examples name the
spec's own language when it states one (e.g. Go `encoding/gob` instead of Java
and Python). Baseline constraints are written in the spec's system name
(`THE Chat_System`). A clause proposed under several criteria of one
requirement is written once. A constraint built from a placeholder the
requirement could not fill ("for the target") is flagged as a draft to
specialize. Every `[SECURITY: …]` line already in the file, hand-written ones
included, is checked on each run for one obligation per line, a named actor
and a unique ID; `--check` runs that validation alone.

Re-running is incremental: only requirements added or changed since the last
run are hardened, constraints a reviewer removed are not proposed again for
requirements already reviewed, and a file with nothing new is left untouched
(`[SKIP] … up to date`).

Engine details, CLI options, and the programmatic API are documented in
[`cwe-to-spec-mapping-library/README.md`](cwe-to-spec-mapping-library/README.md).

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
