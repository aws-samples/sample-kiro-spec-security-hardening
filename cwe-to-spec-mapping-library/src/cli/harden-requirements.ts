#!/usr/bin/env node

import { hardenMarkdownFiles } from "./parse-and-harden.js";
import { basename } from "node:path";

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    console.log(`Usage: harden-requirements <file.md|directory> [file2.md ...]

Reads EARS-format requirement files and hardens them in place.

Each input file is edited in place and only by adding lines: requirement
lines are never changed, split, re-tagged or moved. Requirement-specific
security constraints are inserted beneath the requirement they guard, and
cross-cutting constraints are consolidated into a single "Security Baseline
(Cross-Cutting)" section. Every added line is printed, so the changes can be
reviewed without version control. No copies or sidecar files are written; any
"*_hardened.md" or "*final_requirements.md" left by an older run is removed.

Re-running is incremental: a hidden review marker at the end of the file
records the requirements already hardened, so a re-run hardens only
requirements added or changed since, and does not re-propose constraints a
reviewer removed from requirements already reviewed.

If a directory is given, all .md files in it are processed.

Options:
  --threshold <n>       Confidence threshold (0-1, default: 0.3)
  --max-proposals <n>   Max proposals per requirement (default: 10)
  --no-low-severity     Exclude low-severity CWEs
  --semantic-candidates Print sub-threshold CWEs for agentic adjudication.
                        These are NOT written to the file — an agent reviews
                        them semantically and specializes the ones it confirms
                        (see the harden-spec skill's semantic review pass).
                        By default only object-level authorization gaps are
                        surfaced (the class lexical matching cannot infer).
  --semantic-all        With --semantic-candidates, surface every sub-threshold
                        CWE, not just authorization gaps (noisier, full sweep).
  --semantic-floor <n>  Lower bound for surfacing candidates (0-1, default: 0.05)
  --dry-run             Print the lines that would be added; write nothing.
  --check               Validate only, write nothing: report requirements that
                        are not strict EARS and malformed [SECURITY: ...] lines
                        (two obligations on one line, no actor, missing or
                        duplicate ID). Exits 1 if anything is reported. Run it
                        after editing constraint lines by hand.
  --mark-reviewed       Record every current requirement as reviewed without
                        adding constraints. Use once on a file hardened by an
                        older version (reported as "no review record") so
                        later runs harden only what is added afterwards.
  -h, --help            Show this help

Examples:
  harden-requirements requirements.md
  harden-requirements .kiro/specs/
  harden-requirements req1.md req2.md --threshold 0.5
  harden-requirements requirements.md --semantic-candidates
  harden-requirements requirements.md --dry-run
`);
    process.exit(0);
  }

  let confidenceThreshold = 0.3;
  let maxProposalsPerRequirement = 10;
  let includeLowSeverity = true;
  let showSemanticCandidates = false;
  let semanticCandidateScope: "authz" | "all" = "authz";
  let semanticCandidateFloor = 0.05;
  let dryRun = false;
  let markReviewed = false;
  let check = false;
  const inputArgs: string[] = [];

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--threshold" && args[i + 1]) {
      confidenceThreshold = parseFloat(args[++i]);
    } else if (args[i] === "--max-proposals" && args[i + 1]) {
      maxProposalsPerRequirement = parseInt(args[++i], 10);
    } else if (args[i] === "--no-low-severity") {
      includeLowSeverity = false;
    } else if (args[i] === "--semantic-candidates") {
      showSemanticCandidates = true;
    } else if (args[i] === "--semantic-all") {
      showSemanticCandidates = true;
      semanticCandidateScope = "all";
    } else if (args[i] === "--semantic-floor" && args[i + 1]) {
      semanticCandidateFloor = parseFloat(args[++i]);
    } else if (args[i] === "--dry-run") {
      dryRun = true;
    } else if (args[i] === "--mark-reviewed") {
      markReviewed = true;
    } else if (args[i] === "--check") {
      check = true;
    } else if (args[i].startsWith("--")) {
      console.error(`Error: unknown option ${args[i]}. See --help.`);
      process.exit(1);
    } else {
      inputArgs.push(args[i]);
    }
  }

  if (inputArgs.length === 0) {
    console.error("Error: No input files or directories specified.");
    process.exit(1);
  }

  console.log(`Processing requirement files...\n`);

  const results = await hardenMarkdownFiles(inputArgs, {
    confidenceThreshold,
    maxProposalsPerRequirement,
    includeLowSeverity,
    semanticCandidateFloor,
    semanticCandidateScope,
    dryRun,
    markReviewed,
    check,
  });

  if (results.length === 0) {
    console.error("Error: No EARS requirements found in the provided inputs.");
    process.exit(1);
  }

  let notStrictCount = 0;
  let anchorCount = 0;
  let constraintIssueCount = 0;
  let specializeCount = 0;

  // Problems in [SECURITY: ...] lines already in the file are reported in every
  // mode, since a file that is skipped is exactly the one a reviewer edited.
  const printConstraintWarnings = (result: (typeof results)[number]) => {
    constraintIssueCount += result.constraintWarnings.length;
    for (const w of result.constraintWarnings) {
      console.log(`         [WARN] ${w.location} → ${w.constraintId}: constraint line ${w.message}`);
    }
  };
  const verb = dryRun ? "would be added" : "added";

  for (const result of results) {
    const name = basename(result.inputPath);
    switch (result.mode) {
      case "checked": {
        const notStrict = result.sourceWarnings;
        notStrictCount += notStrict.length;
        const issues = notStrict.length + result.constraintWarnings.length;
        console.log(`  [CHECK] ${name}: ${result.requirementsFound} requirements, ${issues} issue(s). Nothing was written.`);
        for (const warning of notStrict) {
          console.log(`         [WARN] ${warning.requirementId}: ${warning.message}`);
        }
        printConstraintWarnings(result);
        continue;
      }
      case "unrecorded":
        console.log(`  [SKIP] ${name} was hardened by an older version that kept no review record — left untouched.`);
        console.log(`         Run once with --mark-reviewed to record its current requirements as reviewed;`);
        console.log(`         later runs then harden only requirements added after that.`);
        printConstraintWarnings(result);
        continue;
      case "up-to-date":
        console.log(`  [SKIP] ${name} is up to date — every requirement was already hardened.`);
        printConstraintWarnings(result);
        continue;
      case "marked":
        console.log(`  [DONE] ${name}: ${result.requirementsFound} requirement(s) recorded as reviewed${dryRun ? " (dry run, not written)" : ""}.`);
        continue;
    }

    const scope = result.mode === "incremental"
      ? `${result.report.results.length} new or changed requirement(s) of ${result.requirementsFound}`
      : `${result.requirementsFound} requirements`;
    const baseline = result.baselineConstraints > 0
      ? `, ${result.baselineConstraints} baseline constraint(s)`
      : "";
    const constraintLines = result.addedLines.filter((l) => l.text.includes("[SECURITY:")).length;
    console.log(
      `  [${dryRun ? "DRY RUN" : "DONE"}] ${name}: ${scope} checked; ` +
        `${constraintLines} constraint line(s) ${verb} under ${result.requirementsHardened} requirement(s)${baseline}. ` +
        `No existing line was changed.`
    );

    for (const removed of result.removedArtifacts) {
      console.log(`         [CLEANED] removed stale ${basename(removed)}`);
    }

    const notStrict = result.sourceWarnings.filter((w) => /not strict EARS/.test(w.message));
    notStrictCount += notStrict.length;
    anchorCount += result.anchorWarnings.length;

    // Requirements that are not strict EARS need a human, so they are named
    // individually. They are reported only; the tool never rewrites them.
    for (const warning of notStrict) {
      console.log(`         [WARN] ${warning.requirementId}: ${warning.message}`);
    }

    for (const warning of result.anchorWarnings) {
      console.log(`         [WARN] ${warning.requirementId} → ${warning.constraintId}: ${warning.message}`);
    }

    specializeCount += result.specializationWarnings.length;
    for (const w of result.specializationWarnings) {
      console.log(`         [WARN] ${w.location} → ${w.constraintId}: ${w.message}`);
    }

    printConstraintWarnings(result);

    if (result.foldedDuplicates > 0) {
      console.log(
        `         [INFO] ${result.foldedDuplicates} constraint line(s) not repeated: the same clause was ` +
          `already added under an earlier criterion of the same requirement.`
      );
    }

    if (result.suppressedConstraints.length > 0) {
      const byReason = new Map<string, Set<string>>();
      for (const s of result.suppressedConstraints) {
        const key = `${s.cweId}: ${s.reason}`;
        byReason.set(key, (byReason.get(key) ?? new Set()).add(s.requirementId));
      }
      console.log(`         [INFO] Withheld as not applicable to this spec:`);
      for (const [reason, ids] of byReason) {
        console.log(`           ${reason} (${ids.size} requirement(s))`);
      }
    }

    if (result.addedLines.length > 0) {
      console.log(`\n  Lines ${verb} to ${name} (by the original line they follow):`);
      for (const line of result.addedLines) {
        if (line.text.trim()) console.log(`    after ${line.after}: ${line.text.trim()}`);
      }
      console.log("");
    }
  }

  const changed = results.filter((r) => !r.skipped).length;
  if (check) {
    console.log(`\nCheck complete. ${results.length} file(s) checked; nothing was written.`);
  } else {
    console.log(
      `\nHardening complete. ${changed} file(s) ${dryRun ? "previewed (dry run, nothing written)" : "updated in place"}` +
        (changed < results.length ? `, ${results.length - changed} left untouched.` : ".")
    );
  }

  if (notStrictCount > 0) {
    console.log(`  ${notStrictCount} requirement(s) are not strict EARS — review the warnings above. They were not changed.`);
  }
  if (anchorCount > 0) {
    console.log(`  ${anchorCount} constraint group(s) may be anchored to the wrong requirement — review the warnings above.`);
  }
  if (specializeCount > 0) {
    console.log(`  ${specializeCount} constraint(s) use generic placeholder text and must be specialized — review the warnings above.`);
  }
  if (constraintIssueCount > 0) {
    console.log(`  ${constraintIssueCount} [SECURITY: ...] line(s) are malformed — review the warnings above.`);
  }
  if (check && (notStrictCount > 0 || constraintIssueCount > 0)) {
    process.exitCode = 1;
  }

  if (showSemanticCandidates) {
    printSemanticCandidates(results);
  }
}

/**
 * Prints the sub-threshold CWEs the deterministic pass dropped, in a form an
 * agent can act on. These are the gaps lexical matching cannot confirm on its
 * own — most importantly missing object-level authorization checks. The agent
 * adjudicates each question and, for the ones it confirms, adds a constraint
 * specialized to the requirement's domain. Nothing here is written to the file.
 */
function printSemanticCandidates(
  results: Awaited<ReturnType<typeof hardenMarkdownFiles>>
): void {
  const total = results.reduce((n, r) => n + r.semanticCandidates.length, 0);

  console.log(`\n=== SEMANTIC REVIEW (agentic) ===`);
  if (total === 0) {
    console.log(
      `No sub-threshold candidates. Still review every requirement that reads or\n` +
        `mutates a principal-owned resource for a missing relationship predicate —\n` +
        `that gap can carry zero lexical signal.`
    );
    return;
  }

  console.log(
    `${total} sub-threshold candidate(s) need adjudication. They were NOT written\n` +
      `to the file. Confirm each from the requirement's semantics, then add and\n` +
      `domain-specialize the constraint for the ones that hold.`
  );

  for (const result of results) {
    if (result.semanticCandidates.length === 0) continue;
    console.log(`\n  ${basename(result.inputPath)}:`);
    for (const c of result.semanticCandidates) {
      console.log(
        `    ${c.requirementId} — ${c.cweId} ${c.cweName} ` +
          `(lexical ${c.lexicalConfidence.toFixed(2)}, ${c.severity})`
      );
      console.log(`        Requirement: ${c.requirementText}`);
      console.log(`        Adjudicate:  ${c.reasoning.adjudicationQuestion}`);
      for (const constraint of c.candidateConstraints) {
        console.log(
          `        If confirmed → [${constraint.securityPrimitive}] ${constraint.template}`
        );
      }
    }
  }
}

main().catch((err) => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
