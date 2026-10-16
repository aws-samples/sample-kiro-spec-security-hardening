#!/usr/bin/env node

import { hardenMarkdownFiles } from "./parse-and-harden.js";
import { basename } from "node:path";

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    console.log(`Usage: harden-requirements <file.md|directory> [file2.md ...]

Reads EARS-format requirement files and hardens them in place.

Each input file is edited in place: requirement lines are normalized to strict
EARS, requirement-specific security constraints are nested beneath the
requirement they guard, and cross-cutting constraints are consolidated into a
single "Security Baseline (Cross-Cutting)" section. No sidecar files are written;
any "*_hardened.md" or "*final_requirements.md" left by an older run is removed.

Re-running is idempotent — constraints already stated are recognized, not
re-added. Diff against version control to review what hardening changed.

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
  -h, --help            Show this help

Examples:
  harden-requirements requirements.md
  harden-requirements .kiro/specs/
  harden-requirements req1.md req2.md --threshold 0.5
  harden-requirements requirements.md --semantic-candidates
`);
    process.exit(0);
  }

  let confidenceThreshold = 0.3;
  let maxProposalsPerRequirement = 10;
  let includeLowSeverity = true;
  let showSemanticCandidates = false;
  let semanticCandidateScope: "authz" | "all" = "authz";
  let semanticCandidateFloor = 0.05;
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
  });

  if (results.length === 0) {
    console.error("Error: No EARS requirements found in the provided inputs.");
    process.exit(1);
  }

  let splitCount = 0;
  let notStrictCount = 0;
  let anchorCount = 0;

  for (const result of results) {
    if (result.skipped) {
      console.log(`  [SKIP] ${basename(result.inputPath)} is already hardened — left untouched.`);
      console.log(`         To harden newly-added requirements, re-run on the original spec`);
      console.log(`         (e.g. from version control) or remove existing SEC- lines first.`);
      continue;
    }

    const baseline = result.baselineConstraints > 0
      ? `, ${result.baselineConstraints} cross-cutting baseline constraint(s)`
      : "";
    console.log(`  [DONE] ${basename(result.inputPath)} hardened in place (${result.requirementsFound} requirements${baseline})`);

    for (const removed of result.removedArtifacts) {
      console.log(`         [CLEANED] removed stale ${basename(removed)}`);
    }

    const splits = result.sourceWarnings.filter((w) => /split into/.test(w.message));
    const notStrict = result.sourceWarnings.filter((w) => /not strict EARS/.test(w.message));

    splitCount += splits.length;
    notStrictCount += notStrict.length;
    anchorCount += result.anchorWarnings.length;

    // Requirements the tool could not make strict EARS are the ones needing a
    // human, so they are named individually rather than only counted.
    for (const warning of notStrict) {
      console.log(`         [WARN] ${warning.requirementId}: ${warning.message}`);
    }

    for (const warning of result.anchorWarnings) {
      console.log(`         [WARN] ${warning.constraintId}: ${warning.message}`);
    }
  }

  const skipped = results.filter((r) => r.skipped).length;
  const processed = results.length - skipped;
  console.log(
    `\nHardening complete. ${processed} file(s) hardened` +
      (skipped > 0 ? `, ${skipped} already hardened (skipped).` : ".")
  );

  if (splitCount > 0) {
    console.log(`  ${splitCount} compound requirement(s) split into atomic requirements.`);
  }
  if (notStrictCount > 0) {
    console.log(`  ${notStrictCount} requirement(s) could not be normalized to strict EARS — review the warnings above.`);
  }
  if (anchorCount > 0) {
    console.log(`  ${anchorCount} constraint(s) may be anchored to the wrong requirement — review the warnings above.`);
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
