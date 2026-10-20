import type { ProposedRequirement, Requirement, TriggeredCWE } from "../types/index.js";
export interface AnchorWarning {
    requirementId: string;
    constraintId: string;
    message: string;
}
/** True when the requirement's trigger names an internal post-commit event. */
export declare function isInternalEventTrigger(text: string): boolean;
/** True when the constraint presumes an inbound request context. */
export declare function isRequestScopedConstraint(text: string): boolean;
/**
 * Reports request-scoped constraints anchored to internal-event requirements.
 *
 * Returns an empty array for the common case, so a caller can treat a non-empty
 * result as "this spec needs an author's attention".
 */
export declare function checkConstraintAnchoring(requirement: Requirement, proposals: ProposedRequirement[], triggered?: TriggeredCWE[]): AnchorWarning[];
//# sourceMappingURL=anchor-checker.d.ts.map