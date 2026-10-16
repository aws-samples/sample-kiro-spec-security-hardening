# Spec It Safe — Kiro Power

Harden your Kiro specs with security primitives **before** code is written.

Spec It Safe (SIS) analyzes EARS-format requirements, detects which
CWE/OWASP weaknesses each requirement is exposed to, and proposes traceable,
testable security requirements to close the gaps. Security becomes a first-class
construct in the spec — not an afterthought bolted on at code review.

```
Specify (EARS)  →  [ Spec It Safe ]  →  Plan  →  Execute
```

## What's in this power

This repository **is** the power, packaged to the [Agent Plugins v1.0.0](https://agent-plugins.org)
specification so Kiro can install it directly.

```
plugin.json                       # power manifest
skills/
  harden-spec/                    # workflow: run SIS over .kiro/specs and apply the results
  security-primitives-reference/  # CWE→primitive knowledge base + methodology
cwe-to-spec-mapping-library/      # the bundled SIS engine (TypeScript CLI + library)
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
   git clone https://github.com/aws-samples/sample-kiro-spec-security-hardening.git spec-it-safe
   ```

2. Open the **Powers** panel, click **Add Custom Power**, then
   **Import power from a folder**.
3. Choose the `spec-it-safe` directory (it contains `plugin.json`) and click
   **Install**.

**From the Kiro powers registry** (once published): browse
[kiro.dev/powers](https://kiro.dev/powers), select **Spec It Safe**, and click
**Add to Kiro**.

### Kiro CLI

[Kiro CLI](https://kiro.dev/docs/cli/) loads [skills](https://kiro.dev/docs/skills/)
from a project's `.kiro/skills/` directory. Install the two skills there and
clone the engine inside the project, where the `harden-spec` skill can find it:

```bash
cd /path/to/your/project
git clone https://github.com/aws-samples/sample-kiro-spec-security-hardening.git .kiro/spec-it-safe
mkdir -p .kiro/skills
cp -R .kiro/spec-it-safe/skills/harden-spec .kiro/spec-it-safe/skills/security-primitives-reference .kiro/skills/
```

### Building the engine

The first time the `harden-spec` skill runs, it builds the bundled engine. To
build it yourself:

```bash
cd spec-it-safe/cwe-to-spec-mapping-library   # or .kiro/spec-it-safe/... for Kiro CLI
npm install     # installs deps and builds via the `prepare` hook
```

## Quick start: try it on the bundled example

The repository ships a sample spec, `examples/user-management.md`, and its
expected hardened output, `examples/user-management.hardened.md`. To see SIS
work without writing a spec of your own:

```bash
cd spec-it-safe/cwe-to-spec-mapping-library
npm install

# The CLI hardens files in place, so work on a copy.
# Keep the file name: constraint IDs are derived from it.
mkdir -p /tmp/sis-demo
cp examples/user-management.md /tmp/sis-demo/
node dist/cli/harden-requirements.js /tmp/sis-demo/user-management.md --semantic-candidates

# Compare with the expected result (no output means identical)
diff /tmp/sis-demo/user-management.md examples/user-management.hardened.md
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

1. **Finds the engine** in the installed power by its absolute path, and runs
   `npm install` the first time if `dist/` hasn't been built yet.
2. **Lists your specs and confirms once.** "Harden my specs" counts as consent
   to harden every `.kiro/specs/*/requirements.md`. Kiro only asks, in one
   question that lists the specs it found, when it's unclear which spec you mean.
3. **Runs the compiled CLI** with `--semantic-candidates`, then does a semantic
   review pass for missing authorization checks that keyword matching can't see,
   adding domain-specific constraints by hand.
4. **Summarizes** the requirements it hardened, the mandatory constraints grouped
   by CWE, the gaps it added in the semantic pass, and any warnings that need you
   to act.

Review the changes with `git diff`.

### Standalone engine, without Kiro

Build once, then point the compiled CLI at one spec file or a whole specs
directory (directories are searched for `.md` files):

```bash
cd spec-it-safe/cwe-to-spec-mapping-library
npm install          # one-time: installs deps and builds dist/

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
| `-h`, `--help` | Show full usage |

Other ways to run it:

- **From source, no build:** `npm run harden -- <path> [flags]`. This needs the
  `tsx` devDependency. If you see `tsx: command not found`, run
  `npm install --include=dev`.
- **As a global command:** run `npm link` once in
  `cwe-to-spec-mapping-library/`, then call `harden-requirements <path> [flags]`
  from anywhere.

### What it changes

It hardens each `filename.md` **in place**: requirement lines are normalized to
strict EARS, requirement-specific `[SECURITY: …]` constraints are nested under
the requirement they harden, and cross-cutting constraints are consolidated into
one `## Security Baseline (Cross-Cutting)` section. No sidecar files are written.
Run it on a clean git working tree and review the changes with `git diff`.
Re-running on an already-hardened file is a no-op: any file that already has
`[SECURITY: …]` tags is skipped with `[SKIP] … already hardened`. To harden
requirements added after a hardening pass, re-run against the pre-hardening
spec from version control.

Engine details, CLI options, and the programmatic API are documented in
[`cwe-to-spec-mapping-library/README.md`](cwe-to-spec-mapping-library/README.md).

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
