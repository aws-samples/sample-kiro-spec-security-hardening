import type {
  Requirement,
  HardeningResult,
  HardeningReport,
  HardeningSummary,
  ProposedRequirement,
  SemanticCandidate,
  EARSPattern,
  CWEMapping,
} from "../types/index.js";
import { TriggerDetector } from "./trigger-detector.js";
import { CoverageChecker, type CoverageGap } from "./coverage-checker.js";
import {
  classifyEARSPattern,
  isValidActorPhrase,
  toValidEARSClauses,
} from "./ears-normalizer.js";
import { checkConstraintAnchoring, type AnchorWarning } from "./anchor-checker.js";
import {
  collectSemanticCandidates,
  DEFAULT_SEMANTIC_CANDIDATE_FLOOR,
  type SemanticCandidateScope,
} from "./semantic-candidates.js";
import { allMappings } from "../mappings/index.js";

export interface HardeningOptions {
  confidenceThreshold?: number;
  includeLowSeverity?: boolean;
  maxProposalsPerRequirement?: number;
  /**
   * Lower bound for surfacing sub-threshold CWEs as semantic candidates. A CWE
   * scoring in `(floor, confidenceThreshold)` matched weakly but was dropped from
   * the deterministic output; it is collected for agentic adjudication instead.
   */
  semanticCandidateFloor?: number;
  /**
   * Which sub-threshold CWEs to surface as candidates. `authz` (default) keeps
   * only object-level authorization gaps — the class where a weak lexical hit is
   * signal, not noise. `all` surfaces every sub-threshold hit for a full sweep.
   */
  semanticCandidateScope?: SemanticCandidateScope;
}

/**
 * A generated clause that failed EARS validation. Surfaced rather than dropped
 * so a template or extraction defect is visible at generation time.
 */
export interface RejectedClause {
  requirementId: string;
  constraintId: string;
  clause: string;
  errors: string[];
}

/**
 * Verbs that disqualify a captured phrase from an `{input_description}` slot,
 * which must hold a noun phrase.
 */
const VERB_TOKENS_FOR_INPUT = new Set([
  "submits", "submit", "presses", "press", "enters", "enter",
  "requests", "request", "is", "are", "was", "were", "shall", "will",
  "occurs", "occur", "fails", "fail", "detected", "received",
]);

const DEFAULT_OPTIONS: Required<HardeningOptions> = {
  confidenceThreshold: 0.3,
  includeLowSeverity: true,
  maxProposalsPerRequirement: 10,
  semanticCandidateFloor: DEFAULT_SEMANTIC_CANDIDATE_FLOOR,
  semanticCandidateScope: "authz",
};

export class HardeningEngine {
  private triggerDetector: TriggerDetector;
  private coverageChecker: CoverageChecker;
  private mappings: CWEMapping[];
  private rejectedClauses: RejectedClause[] = [];
  private anchorWarnings: AnchorWarning[] = [];
  private semanticCandidates: SemanticCandidate[] = [];

  constructor(mappings: CWEMapping[] = allMappings) {
    this.mappings = mappings;
    this.triggerDetector = new TriggerDetector(mappings);
    this.coverageChecker = new CoverageChecker(mappings);
  }

  /**
   * Clauses rejected by EARS validation during the most recent `harden` call.
   * Empty on a clean run; a non-empty result indicates a template or extraction
   * defect that needs fixing at the source.
   */
  getRejectedClauses(): RejectedClause[] {
    return [...this.rejectedClauses];
  }

  /**
   * Constraints attached to a requirement whose trigger cannot enforce them, from
   * the most recent `harden` call. Advisory: the constraint is still emitted, so
   * a warning here marks a spec an author should re-anchor by hand.
   */
  getAnchorWarnings(): AnchorWarning[] {
    return [...this.anchorWarnings];
  }

  /**
   * Sub-threshold CWEs from the most recent `harden` call — matches too weak for
   * the deterministic output but worth an agent's semantic review. Empty unless
   * a CWE scored inside the `(floor, threshold)` band for some requirement. This
   * is the recall bridge for gaps lexical matching cannot infer (e.g. a missing
   * object-level authorization check); consuming it is what turns SIS from a
   * pattern matcher into a pattern matcher plus an agentic reviewer.
   */
  getSemanticCandidates(): SemanticCandidate[] {
    return [...this.semanticCandidates];
  }

  harden(
    requirements: Requirement[],
    options: HardeningOptions = {}
  ): HardeningReport {
    const opts = { ...DEFAULT_OPTIONS, ...options };
    const results: HardeningResult[] = [];

    // Reset so the accessors reflect this run only.
    this.rejectedClauses = [];
    this.anchorWarnings = [];
    this.semanticCandidates = [];

    for (const requirement of requirements) {
      const result = this.hardenRequirement(requirement, requirements, opts);
      this.anchorWarnings.push(
        ...checkConstraintAnchoring(requirement, result.proposedRequirements)
      );
      results.push(result);
    }

    const summary = this.computeSummary(requirements, results);

    return {
      timestamp: new Date().toISOString(),
      inputRequirements: requirements,
      results,
      summary,
    };
  }

  private hardenRequirement(
    requirement: Requirement,
    allRequirements: Requirement[],
    opts: Required<HardeningOptions>
  ): HardeningResult {
    const triggered = this.triggerDetector.detectTriggers(requirement);

    const filtered = triggered.filter((t) => {
      if (t.confidence < opts.confidenceThreshold) return false;
      if (!opts.includeLowSeverity && t.severity === "low") return false;
      return true;
    });

    // Sub-threshold hits are not applied to the spec, but the ones that scored a
    // weak signal are handed to the agent to adjudicate semantically — this is
    // where a missing object-level authorization check surfaces.
    const promotedCweIds = new Set(filtered.map((t) => t.cweId));
    this.semanticCandidates.push(
      ...collectSemanticCandidates(
        requirement,
        triggered,
        this.mappings,
        promotedCweIds,
        {
          scope: opts.semanticCandidateScope,
          floor: opts.semanticCandidateFloor,
          threshold: opts.confidenceThreshold,
        }
      )
    );

    const gaps = this.coverageChecker.checkCoverage(allRequirements, filtered);

    const proposed = this.generateProposals(requirement, gaps, opts);

    const totalPossibleConstraints = filtered.reduce((sum, t) => {
      const mapping = this.mappings.find((m) => m.id === t.cweId);
      return sum + (mapping?.earsConstraints.length ?? 0);
    }, 0);

    const coveredCount = totalPossibleConstraints - gaps.length;
    const coverageScore =
      totalPossibleConstraints > 0
        ? coveredCount / totalPossibleConstraints
        : 1.0;

    return {
      originalRequirement: requirement,
      triggeredCWEs: filtered,
      proposedRequirements: proposed,
      coverageScore,
    };
  }

  /**
   * Turns coverage gaps into proposals, one per atomic EARS clause.
   *
   * A constraint template may hold several assertions; EARS requires one
   * requirement to carry exactly one testable assertion, so each atom becomes its
   * own proposal with its own id suffix. The cap therefore counts emitted clauses
   * rather than gaps, keeping `maxProposalsPerRequirement` an accurate bound on
   * output size.
   *
   * Clauses that fail validation are collected on `rejectedClauses` rather than
   * dropped, so a generation defect is visible instead of silently removing a
   * security constraint from the spec.
   */
  private generateProposals(
    requirement: Requirement,
    gaps: CoverageGap[],
    opts: Required<HardeningOptions>
  ): ProposedRequirement[] {
    const proposals: ProposedRequirement[] = [];

    for (const gap of gaps) {
      if (proposals.length >= opts.maxProposalsPerRequirement) break;

      const contextualized = this.contextualizeTemplate(
        gap.suggestedTemplate,
        requirement
      );

      const { clauses, rejected } = toValidEARSClauses(contextualized);

      for (const entry of rejected) {
        this.rejectedClauses.push({
          requirementId: requirement.id,
          constraintId: gap.constraintId,
          clause: entry.clause,
          errors: entry.errors,
        });
      }

      const priority = this.determinePriority(gap.severity);

      clauses.forEach((clause, index) => {
        if (proposals.length >= opts.maxProposalsPerRequirement) return;

        // Suffix only when a template atomized, so single-clause ids stay stable.
        const id =
          clauses.length > 1
            ? `SEC-${requirement.id}-${gap.constraintId}-${index + 1}`
            : `SEC-${requirement.id}-${gap.constraintId}`;

        proposals.push({
          id,
          text: clause,
          earsPattern: this.inferPattern(clause),
          addressesCWEs: [gap.cweId],
          securityPrimitives: [gap.missingPrimitive],
          rationale: gap.rationale,
          priority,
        });
      });
    }

    return this.deduplicateProposals(proposals);
  }

  /**
   * Fills a template's `{placeholder}` slots from the parent requirement.
   *
   * Extraction is deliberately conservative: a slot is filled only when the
   * candidate phrase is independently verified as usable in that position. The
   * generic fallback ("a user", "the resource") always yields a grammatical
   * clause, so declining a doubtful extraction costs only specificity, whereas
   * accepting one produces text that is not valid EARS at all.
   */
  private contextualizeTemplate(
    template: string,
    requirement: Requirement
  ): string {
    let result = template;

    const actor = this.extractActor(requirement.text);
    if (actor) {
      result = result.replace(/\{actor\}/g, actor);
    }

    const operation = this.extractOperation(requirement.text);
    if (operation) {
      result = result.replace(/\{operation\}/g, operation);
    }

    const resourceMatch = requirement.text.match(
      /(?:the|a|an)\s+(\w+(?:\s+\w+)?)\s+(?:resource|record|data|entity|object)/i
    );
    if (resourceMatch) {
      result = result.replace(/\{resource\}/g, resourceMatch[1].toLowerCase());
    }

    const input = this.extractInputDescription(requirement.text);
    if (input) {
      result = result.replace(/\{input_description\}/g, input);
    }

    // Generic fallbacks. Applied last so any slot left unfilled above still
    // resolves to grammatical text — no placeholder may reach the output.
    result = result.replace(/\{actor\}/g, "a user");
    result = result.replace(/\{operation\}/g, "the operation");
    result = result.replace(/\{resource\}/g, "the resource");
    result = result.replace(/\{input_description\}/g, "the input");
    result = result.replace(/\{target_state\}/g, "the target state");
    result = result.replace(/\{target\}/g, "the target");
    result = result.replace(/\{required_role\}/g, "the required");
    result = result.replace(/\{high_value_operation\}/g, "the operation");
    result = result.replace(/\{configured_limit\}/g, "the configured limit");

    return result;
  }

  /**
   * Pulls the agent noun phrase out of a requirement's trigger clause.
   *
   * Templates read `WHEN {actor} submits ...`, so the slot needs a bare agent —
   * "a user", "an administrator". The phrase is validated by
   * `isValidActorPhrase`, which rejects both verb-terminated captures (the source
   * of "WHEN user submits submits the input") and non-agent nouns (the source of
   * "WHEN duplicate key submits the input"). Returns undefined when no candidate
   * qualifies, letting the caller fall back to the generic actor.
   */
  private extractActor(text: string): string | undefined {
    const patterns = [
      /\b(?:when|while|if)\s+(?:a|an|the)\s+([a-z]+(?:\s+[a-z]+)?)\s+(?:submits?|requests?|presses?|enters?|provides?|selects?|uploads?|confirms?|attempts?|performs?|initiates?|views?)\b/i,
      /\bthe\s+([a-z]+(?:\s+[a-z]+)?)\s+(?:submits?|requests?|presses?|enters?|provides?|selects?|uploads?|confirms?)\b/i,
    ];

    for (const pattern of patterns) {
      const candidate = text.match(pattern)?.[1];
      if (candidate && isValidActorPhrase(candidate)) {
        const normalized = candidate.trim().toLowerCase();
        return /^(?:a|an|the)\s/.test(normalized)
          ? normalized
          : `a ${normalized}`;
      }
    }

    return undefined;
  }

  /**
   * Extracts the operation verb phrase following `shall`.
   *
   * Only a verb-initial phrase is accepted; `{operation}` slots sit in
   * "requests {operation} on {resource}", where a noun-initial phrase would
   * read as a mangled trigger.
   */
  private extractOperation(text: string): string | undefined {
    const match = text.match(/\bshall\s+([a-z]+(?:\s+[a-z]+){0,2})/i);
    if (!match) return undefined;

    const phrase = match[1].trim().toLowerCase();
    const head = phrase.split(/\s+/)[0];

    // Reject auxiliaries and negation — "shall not", "shall be" carry no operation.
    if (["not", "be", "been", "have", "has", "also", "then"].includes(head)) {
      return undefined;
    }

    return phrase;
  }

  /**
   * Extracts the object of a submission verb for `{input_description}`.
   *
   * The slot appears as "submits {input_description}", so the captured text must
   * be a noun phrase. Anything carrying a finite verb would reproduce the
   * doubled-verb defect, so such candidates are declined.
   */
  private extractInputDescription(text: string): string | undefined {
    const match = text.match(
      /\b(?:submits?|provides?|enters?|supplies?)\s+((?:a|an|the)\s+[\w\s]+?)(?:,|\.|$)/i
    );
    if (!match) return undefined;

    const phrase = match[1].trim().toLowerCase().replace(/\s+/g, " ");
    if (phrase.split(/\s+/).length > 6) return undefined;

    const body = phrase.replace(/^(?:a|an|the)\s+/, "");
    if (body.split(/\s+/).some((word) => VERB_TOKENS_FOR_INPUT.has(word))) {
      return undefined;
    }

    return phrase;
  }

  /**
   * Derives the EARS pattern from a clause's precondition keyword.
   *
   * Delegates to the normalizer so classification cannot drift from validation.
   * The previous implementation mapped `IF` to state-driven and treated
   * `SHALL NOT` as a pattern; `IF` is unwanted-behavior, and `SHALL NOT` is a
   * negative response that may appear under any pattern.
   */
  private inferPattern(template: string): EARSPattern {
    return classifyEARSPattern(template) ?? "ubiquitous";
  }

  private determinePriority(
    severity: "critical" | "high" | "medium" | "low"
  ): "mandatory" | "recommended" | "optional" {
    switch (severity) {
      case "critical":
        return "mandatory";
      case "high":
        return "mandatory";
      case "medium":
        return "recommended";
      case "low":
        return "optional";
    }
  }

  /**
   * Drops proposals whose clause text is already present.
   *
   * Keyed on the normalized clause, not the primitive: atomizing a compound
   * template yields several distinct clauses that legitimately share one
   * primitive, and a primitive-keyed test would discard all but the first —
   * silently losing the "SHALL NOT construct query strings by concatenation"
   * half of the parameterized-query constraint, for instance.
   */
  private deduplicateProposals(
    proposals: ProposedRequirement[]
  ): ProposedRequirement[] {
    const seen = new Set<string>();
    return proposals.filter((p) => {
      const key = p.text.trim().toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  private computeSummary(
    requirements: Requirement[],
    results: HardeningResult[]
  ): HardeningSummary {
    const requirementsWithGaps = results.filter(
      (r) => r.proposedRequirements.length > 0
    ).length;

    const allTriggeredCWEs = new Set(
      results.flatMap((r) => r.triggeredCWEs.map((t) => t.cweId))
    );

    const totalProposed = results.reduce(
      (sum, r) => sum + r.proposedRequirements.length,
      0
    );

    const criticalGaps = results.reduce(
      (sum, r) =>
        sum +
        r.proposedRequirements.filter((p) => p.priority === "mandatory").length,
      0
    );

    const avgCoverage =
      results.length > 0
        ? results.reduce((sum, r) => sum + r.coverageScore, 0) / results.length
        : 1.0;

    return {
      totalRequirements: requirements.length,
      requirementsWithGaps,
      totalCWEsTriggered: allTriggeredCWEs.size,
      totalProposedAdditions: totalProposed,
      criticalGaps,
      overallSecurityScore: Math.round(avgCoverage * 100) / 100,
    };
  }
}

export function formatAsSecurityAnnotatedEARS(
  report: HardeningReport
): string {
  const lines: string[] = [];

  for (const result of report.results) {
    lines.push(`# Original: ${result.originalRequirement.id}`);
    lines.push(result.originalRequirement.text);
    lines.push("");

    if (result.proposedRequirements.length > 0) {
      lines.push(`## Security Hardening (${result.triggeredCWEs.map((t) => t.cweId).join(", ")})`);
      lines.push("");

      for (const proposal of result.proposedRequirements) {
        const secTag = `[SECURITY: ${proposal.securityPrimitives.join(", ")}]`;
        lines.push(`${proposal.id}. ${secTag}`);
        lines.push(proposal.text);
        lines.push(`  Addresses: ${proposal.addressesCWEs.join(", ")}`);
        lines.push(`  Priority: ${proposal.priority}`);
        lines.push(`  Rationale: ${proposal.rationale}`);
        lines.push("");
      }
    } else {
      lines.push("## No security gaps detected");
      lines.push("");
    }

    lines.push("---");
    lines.push("");
  }

  lines.push(`## Summary`);
  lines.push(`- Requirements analyzed: ${report.summary.totalRequirements}`);
  lines.push(`- Requirements with gaps: ${report.summary.requirementsWithGaps}`);
  lines.push(`- CWEs triggered: ${report.summary.totalCWEsTriggered}`);
  lines.push(`- Proposed additions: ${report.summary.totalProposedAdditions}`);
  lines.push(`- Critical gaps: ${report.summary.criticalGaps}`);
  lines.push(`- Security score: ${report.summary.overallSecurityScore}`);

  return lines.join("\n");
}
