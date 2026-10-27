import type { Requirement, HardeningReport, SemanticCandidate, CWEMapping, SpecContext, SuppressedConstraint } from "../types/index.js";
import { type AnchorWarning } from "./anchor-checker.js";
import { type SemanticCandidateScope } from "./semantic-candidates.js";
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
    /**
     * Document-level context (see `detectSpecContext`). When given, constraints
     * for technology the spec does not use, or that the spec declares out of
     * scope, are withheld and reported by `getSuppressedConstraints`. When
     * omitted, no constraint is withheld on context grounds.
     */
    specContext?: SpecContext;
    /**
     * IDs of the requirements to harden. Every requirement passed to `harden`
     * still counts toward coverage, so a constraint already stated elsewhere is
     * not proposed again; only these ones receive proposals. Used for
     * incremental runs over a spec that was already hardened. All when omitted.
     */
    targetRequirementIds?: string[];
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
export declare class HardeningEngine {
    private triggerDetector;
    private coverageChecker;
    private mappings;
    private rejectedClauses;
    private anchorWarnings;
    private semanticCandidates;
    private suppressedConstraints;
    constructor(mappings?: CWEMapping[]);
    /**
     * Clauses rejected by EARS validation during the most recent `harden` call.
     * Empty on a clean run; a non-empty result indicates a template or extraction
     * defect that needs fixing at the source.
     */
    getRejectedClauses(): RejectedClause[];
    /**
     * Constraints attached to a requirement whose trigger cannot enforce them, from
     * the most recent `harden` call. Advisory: the constraint is still emitted, so
     * a warning here marks a spec an author should re-anchor by hand.
     */
    getAnchorWarnings(): AnchorWarning[];
    /**
     * Sub-threshold CWEs from the most recent `harden` call — matches too weak for
     * the deterministic output but worth an agent's semantic review. Empty unless
     * a CWE scored inside the `(floor, threshold)` band for some requirement. This
     * is the recall bridge for gaps lexical matching cannot infer (e.g. a missing
     * object-level authorization check); consuming it is what turns the Specification Hardening Engine from a
     * pattern matcher into a pattern matcher plus an agentic reviewer.
     */
    getSemanticCandidates(): SemanticCandidate[];
    /**
     * Constraints withheld during the most recent `harden` call because the
     * spec's context rules them out — no database for SQL injection, TLS declared
     * out of scope — or because the requirement does not do what the constraint
     * guards (a password-storage rule on a requirement that only sends one).
     */
    getSuppressedConstraints(): SuppressedConstraint[];
    harden(requirements: Requirement[], options?: HardeningOptions): HardeningReport;
    private hardenRequirement;
    /**
     * True when a gap's constraint fits this spec and this requirement. A
     * withheld constraint is recorded with its reason, so the omission shows in
     * the report instead of disappearing.
     */
    private isApplicable;
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
    private generateProposals;
    /**
     * Derives the EARS pattern from a clause's precondition keyword.
     *
     * Delegates to the normalizer so classification cannot drift from validation.
     * The previous implementation mapped `IF` to state-driven and treated
     * `SHALL NOT` as a pattern; `IF` is unwanted-behavior, and `SHALL NOT` is a
     * negative response that may appear under any pattern.
     */
    private inferPattern;
    private determinePriority;
    /**
     * Drops proposals whose clause text is already present.
     *
     * Keyed on the normalized clause, not the primitive: atomizing a compound
     * template yields several distinct clauses that legitimately share one
     * primitive, and a primitive-keyed test would discard all but the first —
     * silently losing the "SHALL NOT construct query strings by concatenation"
     * half of the parameterized-query constraint, for instance.
     */
    private deduplicateProposals;
    private computeSummary;
}
export declare function formatAsSecurityAnnotatedEARS(report: HardeningReport): string;
//# sourceMappingURL=hardening-engine.d.ts.map