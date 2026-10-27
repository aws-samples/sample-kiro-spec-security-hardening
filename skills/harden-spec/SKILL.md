---
name: "harden-spec"
description: "Harden a Kiro spec's EARS requirements with security constraints derived from CWE/OWASP/CVE mappings. Use after functional requirements are finalized and before implementation planning, or whenever the user asks to security-review, harden, or shift-left a requirements/spec document."
license: "MIT-0"
metadata:
  author: "Rajdeep Mukherjee"
  version: "1.0.0"
---

# Harden a Spec with Security Primitives

Runs the bundled **Specification Hardening Engine** over EARS-format requirements to
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

The Specification Hardening Engine ships inside this power at `cwe-to-spec-mapping-library/`. It is a
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

### Setup

The engine ships prebuilt in `dist/` and has no runtime dependencies, so it
needs only Node.js 20 or later. There is nothing to install.

Only if `"$SIS_ENGINE/dist/cli/harden-requirements.js"` is missing (for
example, a checkout made before `dist/` was committed), build it once:

```bash
cd "$SIS_ENGINE" && npm ci --ignore-scripts && npm run build
```

## Workflow

1. **Find the specs and confirm once, before running anything.** The engine
   edits `requirements.md` **in place**, so get consent first, and only ask once.
   - If the user named a file or directory, use that. Otherwise list every
     `.kiro/specs/*/requirements.md` in the workspace by absolute path.
   - **Treat a general request as consent to run on all of them.** "Harden my
     specs", "security-review the specs", "harden everything", or a single spec
     found: run without asking again. Mention which files will change. The CLI
     prints every line it adds, so the change is reviewable even when `.kiro/`
     is not under version control.
   - **Ask only if the request is ambiguous** (e.g. "harden the spec" when there
     are several specs). Ask one question that lists the specs found and
     offers an "all of them" option, then run on what the user picks. Don't
     ask a second time, and don't swap in a scratch copy or the bundled
     example — the user's real spec files are the target.
   - Requirements should be in EARS form. The engine never rewrites a
     requirement; it only reports the ones that are not strict EARS.
   - **Never copy the spec.** Do not create backups, `.orig`/`.bak`/`.sis-raw`
     copies, scratch versions or sidecar files of `requirements.md`, before or
     after the run. The engine edits the one file in place and only adds lines,
     and its output lists every added line. To preview without writing, run it
     with `--dry-run`.

2. **Run the engine** on the confirmed file(s), or on the whole specs directory.
   Always pass absolute paths:

   ```bash
   # Compiled CLI (ships prebuilt in dist/; needs only Node):
   node "$SIS_ENGINE/dist/cli/harden-requirements.js" /abs/path/to/.kiro/specs/ --semantic-candidates
   # …or a single file:
   node "$SIS_ENGINE/dist/cli/harden-requirements.js" /abs/path/to/.kiro/specs/my-feature/requirements.md --semantic-candidates
   ```

   `[SKIP] … up to date` means every requirement in that file was already
   hardened. `[SKIP] … no review record` means the file was hardened by an
   older version of this power; see step 6.

   Useful options: `--threshold <0-1>` (confidence, default 0.3),
   `--max-proposals <n>` (default 10), `--no-low-severity`,
   `--semantic-candidates` (print sub-threshold CWEs for you to adjudicate — see
   step 3), `--semantic-floor <0-1>` (default 0.05), `--dry-run` (print what
   would be added, write nothing), `--check` (validate only; see step 3),
   `--mark-reviewed` (see step 6).

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
   traceable, and explicit principles below. Re-running hardens only
   requirements added or changed since (step 6), so make these additions in
   this same pass — re-running will not add them for you.

   **Format of a hand-added line** (the engine checks every one, step 4):
   - **ID:** `SEC-<requirement>-SEM-<CWE number>-<n>`, where `<requirement>`
     is the ID the engine uses for that requirement (`REQ-11.2` for criterion 2
     of "Requirement 11"), e.g. `SEC-REQ-11.2-SEM-862-1`. Baseline lines use
     the next free `SEC-BASELINE-<n>`. Every ID must be unique in the file.
   - **One obligation per line.** "SHALL scope X and SHALL NOT grant Y" is
     two constraints: write two lines, both in EARS form.
   - **Number** it after the requirement's last existing child (`2.4.`, `2.5.`).

   **Work through every `=== SEMANTIC REVIEW ===` entry** and record a verdict
   for each: confirmed (and the constraint you added) or rejected (and why).
   You report these in step 5.

   **Curate the engine's output in the same pass.** The engine reads one
   requirement at a time and cannot know every design decision. Remove or
   rewrite a generated `[SECURITY: …]` line that does not fit the system (for
   example, a constraint for a component the system does not have), and say
   why in your summary. Edit only `[SECURITY: …]` lines and the baseline
   section. Never edit, split, re-tag, reorder or "restore" a requirement line:
   its wording is the user's, and changing it changes what it obliges.

   Every line flagged `built with generic text "the target" …` (or "the
   operation", "the resource", "the configured limit") is a draft. Rewrite it
   in the requirement's own terms (which role, which object, which limit), or
   remove it.

   **Then validate your edits:**

   ```bash
   node "$SIS_ENGINE/dist/cli/harden-requirements.js" /abs/path/to/requirements.md --check
   ```

   `--check` writes nothing. It reports requirements that are not strict EARS
   and every malformed `[SECURITY: …]` line: two obligations on one line, no
   named actor, a malformed trigger, or a missing or duplicate ID. It exits
   with status 1 if it reports anything. Fix the constraint lines until it
   reports none of them.

4. **Read the result.** The engine edits the input `filename.md` **in place**,
   and only by adding lines. Every original line, requirement lines included,
   stays exactly as written: nothing is split, re-tagged, reworded or moved.
   Requirement-specific `[SECURITY: …]` constraints are inserted under the
   requirement they harden, in the parent's own subject (e.g. `THE Cron_SDK
   SHALL`). Cross-cutting constraints (those that would otherwise repeat under
   most requirements) are consolidated into one
   `## Security Baseline (Cross-Cutting)` section at the end. A hidden
   `<!-- spec-it-safe:reviewed … -->` comment at the very end records which
   requirements were hardened; leave it in place. The CLI output lists every
   added line by the original line it follows. The engine refuses to write a
   file if any original line would not survive unchanged.

5. **Surface the results to the user.** Summarize concisely:
   - How many requirements were hardened vs left as-is.
   - The highest-priority (`mandatory`) constraints added, grouped by the CWE they close.
   - The gaps you added in the semantic review pass (step 3) that the deterministic
     engine could not infer, and why each holds.
   - The verdict on **every** semantic-review candidate: how many there were,
     which you confirmed, and why you rejected the rest.
   - Every generated line you rewrote or removed, and why.
   - The result of the final `--check` run. Say what it covers: it validates
     EARS structure, IDs and one-obligation-per-line, not whether a constraint
     is complete or correct. Do not describe a clean check as more than that.
   - Any **warnings** the CLI printed. Warnings name the requirement by its
     criterion number and line, e.g. `7.8 (line 213)`:
     - `[WARN] … not strict EARS` — the requirement does not follow EARS; name
       it and let the user decide. The engine did not change it, and neither
       should you. The check is structural only: a truncated requirement such
       as `THE Chat_Server SHALL create.` passes without a warning. If you
       notice a requirement whose response is incomplete, point it out to the
       user rather than fixing it.
     - `[WARN] … matched … only on the keywords …` — the CWE fired on loose
       keywords with no pattern of the weakness, so the named constraints may be
       misplaced. Decide from the requirement's meaning: keep, move, or drop
       them, and say which.
     - `[WARN] … built with generic text …` — the constraint was built from a
       template slot the requirement did not fill; specialize or remove it.
     - `[WARN] … constraint line …` — a `[SECURITY: …]` line already in the
       file is malformed (compound, actorless, missing or duplicate ID). These
       are reported on every run, including `up to date` ones; fix the line.
     - `[WARN] … request-scoped but … post-commit event` — the constraint
       cannot be enforced at that point in the flow; move it to the
       request-entry requirement.
   - `[INFO] … not repeated` — a clause proposed under several criteria of the
     same requirement section was written once, under the first. Nothing to do.
   - `[INFO] Withheld as not applicable` — constraints the engine withheld
     because the spec shows no matching component (no SQL database, no
     browser) or declares the topic out of scope (e.g. TLS). Mention them, and
     propose a compensating control by hand where one fits.

6. **Re-runs and safety.** Consent comes from step 1 — don't ask again here.
   Hardening is strictly additive — it never changes, removes or weakens a
   requirement. Re-running is **incremental**: the review marker records each
   requirement already hardened, so a re-run hardens only requirements added or
   changed since. It does not re-propose constraints a reviewer removed from a
   requirement that was already reviewed, and constraints already stated
   anywhere in the file are not added twice. With nothing new, the run is a
   no-op (`[SKIP] … up to date`).

   A file hardened by an older version of this power has `[SECURITY: …]` lines
   but no review marker, and is skipped (`[SKIP] … no review record`). Once its
   current content is reviewed, run the CLI on it with `--mark-reviewed`. That
   adds only the marker, so later runs harden just the requirements added
   afterwards. Never reconstruct a "pre-hardening" copy to re-run against.

## Principles (do not violate)

1. **Contextual** — only add constraints relevant to each requirement's semantics
   (file-upload requirements get upload validation, not CSRF).
2. **Additive** — never drop, weaken, split or reword a requirement. Security
   constraints are added beside it; the requirement's own text stays verbatim.
3. **Explicit** — state security invariants in the spec; do not assume them from
   middleware or existing code. The coding agent implements the spec literally.
4. **Traceable** — every constraint maps to a specific CWE with a rationale.
5. **Defense in depth** — for critical CWEs, layered constraints are expected
   (e.g. parameterized queries *and* input validation for SQL injection).

## If the engine can't run

If Node/npm is unavailable, fall back to the `security-primitives-reference`
skill and apply the CWE→primitive methodology manually. Prefer the engine
whenever it can run — its output is deterministic and fully traceable.
