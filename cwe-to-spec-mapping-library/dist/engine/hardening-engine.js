import { contextSuppressionReason } from "./spec-context.js";
import { fillTemplate, resolveTemplate } from "./template-filler.js";
import { TriggerDetector } from "./trigger-detector.js";
import { CoverageChecker } from "./coverage-checker.js";
import { classifyEARSPattern, toValidEARSClauses, } from "./ears-normalizer.js";
import { checkConstraintAnchoring } from "./anchor-checker.js";
import { collectSemanticCandidates, DEFAULT_SEMANTIC_CANDIDATE_FLOOR, } from "./semantic-candidates.js";
import { allMappings } from "../mappings/index.js";
const DEFAULT_OPTIONS = {
    confidenceThreshold: 0.3,
    includeLowSeverity: true,
    maxProposalsPerRequirement: 10,
    semanticCandidateFloor: DEFAULT_SEMANTIC_CANDIDATE_FLOOR,
    semanticCandidateScope: "authz",
};
export class HardeningEngine {
    triggerDetector;
    coverageChecker;
    mappings;
    rejectedClauses = [];
    anchorWarnings = [];
    semanticCandidates = [];
    suppressedConstraints = [];
    constructor(mappings = allMappings) {
        this.mappings = mappings;
        this.triggerDetector = new TriggerDetector(mappings);
        this.coverageChecker = new CoverageChecker(mappings);
    }
    /**
     * Clauses rejected by EARS validation during the most recent `harden` call.
     * Empty on a clean run; a non-empty result indicates a template or extraction
     * defect that needs fixing at the source.
     */
    getRejectedClauses() {
        return [...this.rejectedClauses];
    }
    /**
     * Constraints attached to a requirement whose trigger cannot enforce them, from
     * the most recent `harden` call. Advisory: the constraint is still emitted, so
     * a warning here marks a spec an author should re-anchor by hand.
     */
    getAnchorWarnings() {
        return [...this.anchorWarnings];
    }
    /**
     * Sub-threshold CWEs from the most recent `harden` call — matches too weak for
     * the deterministic output but worth an agent's semantic review. Empty unless
     * a CWE scored inside the `(floor, threshold)` band for some requirement. This
     * is the recall bridge for gaps lexical matching cannot infer (e.g. a missing
     * object-level authorization check); consuming it is what turns the Specification Hardening Engine from a
     * pattern matcher into a pattern matcher plus an agentic reviewer.
     */
    getSemanticCandidates() {
        return [...this.semanticCandidates];
    }
    /**
     * Constraints withheld during the most recent `harden` call because the
     * spec's context rules them out — no database for SQL injection, TLS declared
     * out of scope — or because the requirement does not do what the constraint
     * guards (a password-storage rule on a requirement that only sends one).
     */
    getSuppressedConstraints() {
        return [...this.suppressedConstraints];
    }
    harden(requirements, options = {}) {
        const opts = { ...DEFAULT_OPTIONS, ...options };
        const results = [];
        // Reset so the accessors reflect this run only.
        this.rejectedClauses = [];
        this.anchorWarnings = [];
        this.semanticCandidates = [];
        this.suppressedConstraints = [];
        const targets = opts.targetRequirementIds
            ? new Set(opts.targetRequirementIds)
            : undefined;
        for (const requirement of requirements) {
            if (targets && !targets.has(requirement.id))
                continue;
            const result = this.hardenRequirement(requirement, requirements, opts);
            this.anchorWarnings.push(...checkConstraintAnchoring(requirement, result.proposedRequirements, result.triggeredCWEs));
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
    hardenRequirement(requirement, allRequirements, opts) {
        const triggered = this.triggerDetector.detectTriggers(requirement);
        const filtered = triggered.filter((t) => {
            if (t.confidence < opts.confidenceThreshold)
                return false;
            if (!opts.includeLowSeverity && t.severity === "low")
                return false;
            return true;
        });
        // Sub-threshold hits are not applied to the spec, but the ones that scored a
        // weak signal are handed to the agent to adjudicate semantically — this is
        // where a missing object-level authorization check surfaces.
        const promotedCweIds = new Set(filtered.map((t) => t.cweId));
        const candidates = collectSemanticCandidates(requirement, triggered, this.mappings, promotedCweIds, {
            scope: opts.semanticCandidateScope,
            floor: opts.semanticCandidateFloor,
            threshold: opts.confidenceThreshold,
        });
        // Show each candidate constraint as it would read for this requirement and
        // spec, not as a raw template with `{actor}` slots.
        for (const candidate of candidates) {
            const mapping = this.mappings.find((m) => m.id === candidate.cweId);
            candidate.candidateConstraints = candidate.candidateConstraints.map((c) => {
                const constraint = mapping?.earsConstraints.find((e) => e.id === c.id);
                const template = constraint ? resolveTemplate(constraint, opts.specContext) : c.template;
                const filled = fillTemplate(template, requirement.text).text;
                // In the requirement's own subject, as inline constraints are written.
                const component = requirement.text.match(/\bTHE\s+([A-Za-z][\w-]*)\s+SHALL\b/i)?.[1];
                return {
                    ...c,
                    template: component && !/^system$/i.test(component)
                        ? filled.replace(/\bTHE SYSTEM\b/g, `THE ${component}`)
                        : filled,
                };
            });
        }
        this.semanticCandidates.push(...candidates);
        const gaps = this.coverageChecker
            .checkCoverage(allRequirements, filtered)
            .filter((gap) => this.isApplicable(gap, requirement, opts));
        const proposed = this.generateProposals(requirement, gaps, opts);
        const totalPossibleConstraints = filtered.reduce((sum, t) => {
            const mapping = this.mappings.find((m) => m.id === t.cweId);
            return sum + (mapping?.earsConstraints.length ?? 0);
        }, 0);
        const coveredCount = totalPossibleConstraints - gaps.length;
        const coverageScore = totalPossibleConstraints > 0
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
     * True when a gap's constraint fits this spec and this requirement. A
     * withheld constraint is recorded with its reason, so the omission shows in
     * the report instead of disappearing.
     */
    isApplicable(gap, requirement, opts) {
        const mapping = this.mappings.find((m) => m.id === gap.cweId);
        const constraint = mapping?.earsConstraints.find((c) => c.id === gap.constraintId);
        if (!mapping || !constraint)
            return true;
        let reason = opts.specContext
            ? contextSuppressionReason(mapping, constraint, opts.specContext)
            : undefined;
        if (!reason && constraint.appliesTo && !new RegExp(constraint.appliesTo, "i").test(requirement.text)) {
            reason = `requirement does not do what ${constraint.securityPrimitive} guards`;
        }
        if (!reason)
            return true;
        this.suppressedConstraints.push({
            requirementId: requirement.id,
            cweId: gap.cweId,
            constraintId: gap.constraintId,
            reason,
        });
        return false;
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
    generateProposals(requirement, gaps, opts) {
        const proposals = [];
        for (const gap of gaps) {
            if (proposals.length >= opts.maxProposalsPerRequirement)
                break;
            const mapping = this.mappings.find((m) => m.id === gap.cweId);
            const constraint = mapping?.earsConstraints.find((c) => c.id === gap.constraintId);
            const template = constraint
                ? resolveTemplate(constraint, opts.specContext)
                : gap.suggestedTemplate;
            const filled = fillTemplate(template, requirement.text);
            const { clauses, rejected } = toValidEARSClauses(filled.text);
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
                if (proposals.length >= opts.maxProposalsPerRequirement)
                    return;
                // Suffix only when a template atomized, so single-clause ids stay stable.
                const id = clauses.length > 1
                    ? `SEC-${requirement.id}-${gap.constraintId}-${index + 1}`
                    : `SEC-${requirement.id}-${gap.constraintId}`;
                // Only the generic fallbacks that ended up in this clause matter.
                const genericSlots = filled.genericSlots.filter((g) => clause.includes(g.filledWith));
                proposals.push({
                    id,
                    text: clause,
                    earsPattern: this.inferPattern(clause),
                    addressesCWEs: [gap.cweId],
                    securityPrimitives: [gap.missingPrimitive],
                    rationale: gap.rationale,
                    priority,
                    ...(genericSlots.length > 0 ? { genericSlots } : {}),
                });
            });
        }
        return this.deduplicateProposals(proposals);
    }
    /**
     * Derives the EARS pattern from a clause's precondition keyword.
     *
     * Delegates to the normalizer so classification cannot drift from validation.
     * The previous implementation mapped `IF` to state-driven and treated
     * `SHALL NOT` as a pattern; `IF` is unwanted-behavior, and `SHALL NOT` is a
     * negative response that may appear under any pattern.
     */
    inferPattern(template) {
        return classifyEARSPattern(template) ?? "ubiquitous";
    }
    determinePriority(severity) {
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
    deduplicateProposals(proposals) {
        const seen = new Set();
        return proposals.filter((p) => {
            const key = p.text.trim().toLowerCase();
            if (seen.has(key))
                return false;
            seen.add(key);
            return true;
        });
    }
    computeSummary(requirements, results) {
        const requirementsWithGaps = results.filter((r) => r.proposedRequirements.length > 0).length;
        const allTriggeredCWEs = new Set(results.flatMap((r) => r.triggeredCWEs.map((t) => t.cweId)));
        const totalProposed = results.reduce((sum, r) => sum + r.proposedRequirements.length, 0);
        const criticalGaps = results.reduce((sum, r) => sum +
            r.proposedRequirements.filter((p) => p.priority === "mandatory").length, 0);
        const avgCoverage = results.length > 0
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
export function formatAsSecurityAnnotatedEARS(report) {
    const lines = [];
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
        }
        else {
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
//# sourceMappingURL=hardening-engine.js.map