---
name: "harden-spec"
description: "Harden a Kiro spec's EARS requirements with security constraints derived from CWE/OWASP/CVE mappings. Use after functional requirements are finalized and before implementation planning, or whenever the user asks to security-review, harden, or shift-left a requirements/spec document."
license: "MIT-0"
metadata:
  author: "Rajdeep Mukherjee"
  version: "1.0.0"
---

# Harden a Spec with Security Primitives

Runs the bundled **Spec It Safe (SIS)** engine over EARS-format requirements to
find missing security constraints and propose traceable, testable EARS
requirements that close them — before a single line of code is written.

Security is cheapest to fix at the requirements phase. This skill sits between
requirements authoring and implementation planning in the Kiro workflow:

```
Specify (EARS)  →  [ harden-spec ]  →  Plan  →  Execute
```

## When to use

- The user finished writing functional requirements and is about to plan/implement.
- The user asks to "harden", "security review", "shift left", or "add security requirements" to a spec.
- A `.kiro/specs/*/requirements.md` file exists and hasn't been security-reviewed.

## The engine

The SIS engine ships inside this power at `cwe-to-spec-mapping-library/`. It is a
deterministic TypeScript CLI — prefer running it over hand-authoring
constraints, so results are reproducible and every constraint is CWE-traceable.

### Locate the engine (absolute path)

The engine lives in the **installed power**, not in the user's workspace, so a
relative `cd cwe-to-spec-mapping-library` will usually fail. Resolve its absolute
path once and reuse it as `$SIS_ENGINE` for every command below:

1. **From this skill file.** This `SKILL.md` is at
   `<power-root>/skills/harden-spec/SKILL.md`; the engine is
   `<power-root>/cwe-to-spec-mapping-library`. Take the directory you loaded this
   skill from and go up two levels.
2. **If you don't know where the skill was loaded from**, search the usual
   install locations:

   ```bash
   find ~/.kiro "$PWD" -type f -path '*cwe-to-spec-mapping-library/package.json' \
     -not -path '*/node_modules/*' 2>/dev/null
   ```

Confirm the right folder by checking that its `package.json` has
`"name": "@sis/cwe-to-spec-mapping"`, then:

```bash
SIS_ENGINE=/abs/path/to/cwe-to-spec-mapping-library
```

### One-time setup

```bash
cd "$SIS_ENGINE" && npm install     # installs deps and builds dist/ via the `prepare` hook
```

Skip it if `"$SIS_ENGINE/dist/cli/harden-requirements.js"` already exists.
`npm install` is idempotent, so running it again is safe.

## Workflow

1. **Find the specs and confirm once, before running anything.** The engine
   edits `requirements.md` **in place**, so get consent first, and only ask once.
   - If the user named a file or directory, use that. Otherwise list every
     `.kiro/specs/*/requirements.md` in the workspace by absolute path.
   - **Treat a general request as consent to run on all of them.** "Harden my
     specs", "security-review the specs", "harden everything", or a single spec
     found: run without asking again. Mention which files will change and that
     `git diff` shows exactly what was added.
   - **Ask only if the request is ambiguous** (e.g. "harden the spec" when there
     are several specs). Ask one question that lists the specs found and
     offers an "all of them" option, then run on what the user picks. Don't
     ask a second time, and don't swap in a scratch copy or the bundled
     example — the user's real spec files are the target.
   - Requirements should be in EARS form; the engine tolerates and normalizes
     near-EARS prose but flags what it cannot normalize.

2. **Run the engine** on the confirmed file(s), or on the whole specs directory.
   Always pass absolute paths. **Use the compiled CLI first:**

   ```bash
   # Primary — compiled CLI (needs only Node; built by `npm install`):
   node "$SIS_ENGINE/dist/cli/harden-requirements.js" /abs/path/to/.kiro/specs/ --semantic-candidates
   # …or a single file:
   node "$SIS_ENGINE/dist/cli/harden-requirements.js" /abs/path/to/.kiro/specs/my-feature/requirements.md --semantic-candidates
   ```

   **Fallback — run from source with tsx.** Use this only if `dist/` is missing
   and `npm install` can't rebuild it. `tsx` is a devDependency, so it is missing
   if dev dependencies were left out; if you see `tsx: command not found`, run
   `npm install --include=dev` in `$SIS_ENGINE` first:

   ```bash
   cd "$SIS_ENGINE" && npm run harden -- /abs/path/to/.kiro/specs/ --semantic-candidates
   ```

   A `[SKIP] … already hardened` line means that file already has
   `[SECURITY: …]` tags and was left untouched (see the re-run note in step 6).

   Useful options: `--threshold <0-1>` (confidence, default 0.3),
   `--max-proposals <n>` (default 10), `--no-low-severity`,
   `--semantic-candidates` (print sub-threshold CWEs for you to adjudicate — see
   step 3), `--semantic-floor <0-1>` (default 0.05).

3. **Run the semantic review pass (agentic — this is your job, not the engine's).**
   The deterministic engine matches lexically: it fires a CWE only when keywords
   or patterns are *present*. A whole class of defect is invisible to it — most
   importantly **object-level authorization** gaps (CWE-862/639/284), where the
   vulnerability is a *missing* relationship predicate rather than any word on the
   page. "Any authenticated clinician can read any patient's notes" names a caller
   and a resource but never constrains the care relationship between them; lexical
   matching scores this below threshold and drops it. Closing that gap is what you
   add on top of the engine.

   Two inputs drive this pass:

   a. **The `=== SEMANTIC REVIEW ===` block** the engine prints under
      `--semantic-candidates`. Each entry is a CWE the engine saw a weak signal
      for but discarded, with an **Adjudicate** question and the constraint to add
      if the answer is yes. By default this lists only object-level authorization
      gaps — the class where a weak lexical hit is genuine signal; add
      `--semantic-all` for a noisier full sweep of every sub-threshold CWE. Work
      through every entry: answer the question *from the requirement's meaning*,
      not from keywords.

   b. **A boundary sweep of every requirement**, including those with no candidate
      (the gap can carry zero lexical signal). For each requirement that reads,
      returns, or mutates a resource tied to a principal, ask: *is the relationship
      between the caller and that specific resource constrained?* If a caller can
      reach any instance of the resource with no ownership, tenancy, or explicit
      relationship check, that is a CWE-862 object-level authorization gap.

   For every gap you confirm, add a constraint **by hand** in the same format the
   engine uses — a `[SECURITY: <primitive>]`-tagged EARS line nested under the
   requirement it hardens — and **specialize it to the domain**. Do not paste the
   generic template: turn "matches the resource owner" into the concrete predicate,
   e.g. *"THE SYSTEM SHALL return clinical notes only for patients with whom the
   requesting clinician has an active care relationship."* Keep the additive,
   traceable, and explicit principles below. Because the engine no-ops on an
   already-hardened file (step 6), make these additions in this same pass —
   re-running will not add them for you.

4. **Read the result.** The engine edits the input `filename.md` **in place** —
   there are no sidecar files. Each requirement line is normalized to strict EARS;
   requirement-specific `[SECURITY: …]` constraints are nested under the
   requirement they harden — in the parent's own subject (e.g. `THE Cron_SDK
   SHALL`) to match the spec's voice and keep component traceability; and
   cross-cutting constraints (those that would
   otherwise repeat under most requirements) are consolidated into one
   `## Security Baseline (Cross-Cutting)` section at the end. `git diff` the file
   to see exactly what hardening added. The `report` returned to you still carries
   the full triggered-CWE / rationale detail to explain *why*.

5. **Surface the results to the user.** Summarize concisely:
   - How many requirements were hardened vs left as-is.
   - The highest-priority (`mandatory`) constraints added, grouped by the CWE they close.
   - The gaps you added in the semantic review pass (step 3) that the deterministic
     engine could not infer, and why each holds.
   - Any **warnings** the CLI printed:
     - `[WARN] … not strict EARS` — the requirement needs a human to rewrite; name it.
     - `[WARN] … may be anchored to the wrong requirement` — a constraint may be attached to the wrong requirement; ask the user to confirm placement.
     - "compound requirement split" — a requirement was decomposed into atomic ones.

6. **Re-runs and safety.** Consent comes from step 1 — don't ask again here.
   Hardening is strictly additive — it never removes or weakens a functional
   requirement, and `git diff` shows exactly what it added. Re-running on an
   already-hardened file is a **no-op**: the tool detects the `[SECURITY: …]`
   tags and leaves the file untouched (its EARS-split output does not round-trip,
   so re-processing would corrupt it). To harden requirements added *after* a
   hardening pass, re-run against the pre-hardening spec from version control.

## Principles (do not violate)

1. **Contextual** — only add constraints relevant to each requirement's semantics
   (file-upload requirements get upload validation, not CSRF).
2. **Additive** — never drop or weaken a functional requirement.
3. **Explicit** — state security invariants in the spec; do not assume them from
   middleware or existing code. The coding agent implements the spec literally.
4. **Traceable** — every constraint maps to a specific CWE with a rationale.
5. **Defense in depth** — for critical CWEs, layered constraints are expected
   (e.g. parameterized queries *and* input validation for SQL injection).

## If the engine can't run

If Node/npm is unavailable, fall back to the `security-primitives-reference`
skill and apply the CWE→primitive methodology manually. Prefer the engine
whenever it can run — its output is deterministic and fully traceable.
