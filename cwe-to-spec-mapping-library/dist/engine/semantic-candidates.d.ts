import type { CWEMapping, Requirement, SemanticCandidate, TriggeredCWE } from "../types/index.js";
/**
 * Lexical scores below the confidence threshold but above this floor are treated
 * as "whiffs" — one weak signal worth an agent's second look — rather than noise.
 * The lowest score the detector can emit for a single keyword hit is 0.16, so a
 * floor of 0.05 keeps that band while discarding the truly incidental.
 */
export declare const DEFAULT_SEMANTIC_CANDIDATE_FLOOR = 0.05;
/** Cap on candidates surfaced per requirement, so a broad sweep cannot flood. */
export declare const DEFAULT_MAX_SEMANTIC_CANDIDATES = 8;
/**
 * Which classes of sub-threshold CWE to surface.
 *
 * `authz` (default) restricts to *object-level authorization*: the class where a
 * weak lexical hit genuinely signals a defect, because the vulnerability is a
 * missing relationship predicate between caller and resource, not a keyword.
 * Widening the confidence threshold would never recover these correctly, and
 * they are indistinguishable — lexically — from incidental keyword matches, so
 * an agent must adjudicate them. `all` additionally surfaces every other
 * sub-threshold hit for a thorough manual sweep, at the cost of noise.
 */
export type SemanticCandidateScope = "authz" | "all";
export interface SemanticCandidateOptions {
    scope?: SemanticCandidateScope;
    floor?: number;
    threshold?: number;
    maxPerRequirement?: number;
}
/**
 * Collects the sub-threshold CWEs for one requirement as semantic candidates.
 *
 * `triggered` is the *unfiltered* detector output; `promotedCweIds` are the CWEs
 * that cleared the threshold and are already handled deterministically, so they
 * are excluded here to avoid proposing the same constraint twice. Results are
 * ordered most-relevant-first (object-level authz, then severity, then
 * confidence) and capped so a broad sweep cannot bury the signal.
 */
export declare function collectSemanticCandidates(requirement: Requirement, triggered: TriggeredCWE[], mappings: CWEMapping[], promotedCweIds: Set<string>, options?: SemanticCandidateOptions): SemanticCandidate[];
//# sourceMappingURL=semantic-candidates.d.ts.map