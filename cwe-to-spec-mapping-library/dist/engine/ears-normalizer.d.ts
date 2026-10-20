import type { EARSPattern } from "../types/index.js";
/**
 * True when a "before <event>" qualifier names an event that can become a
 * leading trigger. A gerund phrase becomes `WHILE <object> is being <done>`, and
 * a subject-and-verb clause becomes `WHEN <clause>`. A bare noun — "before use",
 * "before deployment", "before the deadline" — names no event, so moving it
 * produces a trigger such as `WHEN use,` that states nothing testable. Such a
 * qualifier stays where it is, in the response.
 */
export declare function isHoistableEvent(event: string): boolean;
export interface EARSValidationResult {
    valid: boolean;
    pattern?: EARSPattern;
    errors: string[];
}
/**
 * Rewrites a trailing "before <event>" qualifier into a leading EARS trigger.
 *
 * `THE SYSTEM SHALL verify ownership before executing the operation.`
 *   becomes
 * `WHILE the operation is being executed, THE SYSTEM SHALL verify ownership.`
 *
 * A clause that already carries a precondition is returned unchanged: stacking a
 * second trigger onto it would silently narrow the requirement's scope, which is
 * a semantic change rather than the formatting repair intended here.
 */
export declare function hoistEmbeddedPrecondition(clause: string): string;
/**
 * Decides whether an extracted phrase may be substituted into an `{actor}` slot.
 *
 * Templates read `WHEN {actor} submits ...`, so the slot must hold a bare agent
 * noun phrase. Admitting a phrase whose head is a verb is what produced the
 * "WHEN user submits submits the input" defect; admitting a non-agent noun is
 * what produced "WHEN duplicate key submits the input".
 */
export declare function isValidActorPhrase(phrase: string): boolean;
/**
 * Splits a template into atomic clauses, propagating the precondition.
 *
 * When a triggered template is atomized, later sentences inherit the leading
 * trigger. Dropping it would silently widen each follow-on assertion from
 * "only under this condition" to "at all times".
 */
export declare function atomizeTemplate(template: string): string[];
/**
 * Repairs the mechanical grammar deviations a template can carry: a missing
 * `THEN` after an `IF` precondition, a lowercase actor, and doubled whitespace.
 *
 * Semantic defects — an unfilled placeholder, a passive clause, an unusable
 * trigger — are not repairable here and are surfaced by `validateEARSClause`
 * instead of being papered over.
 */
export declare function normalizeEARSClause(clause: string): string;
/**
 * Classifies a clause by its EARS pattern using the precondition keywords alone.
 *
 * `SHALL NOT` is a negative *response*, not a pattern — a common misreading that
 * conflates it with the unwanted-behavior form. Only `IF ..., THEN` is
 * unwanted-behavior.
 */
export declare function classifyEARSPattern(clause: string): EARSPattern | undefined;
/**
 * Validates a clause against the strict EARS grammar. Every generated clause is
 * checked before it is written, so violations fail loudly at generation time
 * rather than surfacing as unparseable text in a delivered spec.
 */
export declare function validateEARSClause(clause: string): EARSValidationResult;
/**
 * Full pipeline for one template: atomize, normalize, validate.
 *
 * Invalid clauses are returned separately rather than dropped silently, so the
 * caller can surface them; a spec that quietly loses a security constraint is
 * more dangerous than one that reports a generation failure.
 */
export declare function toValidEARSClauses(template: string): {
    clauses: string[];
    rejected: Array<{
        clause: string;
        errors: string[];
    }>;
};
//# sourceMappingURL=ears-normalizer.d.ts.map