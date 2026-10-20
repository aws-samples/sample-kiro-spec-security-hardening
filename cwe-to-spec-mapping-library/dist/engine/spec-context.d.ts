import type { CWEMapping, EARSConstraint, SpecContext } from "../types/index.js";
/**
 * Reads a spec document once and returns its context.
 *
 * Out-of-scope statements are collected at sentence level, so a long
 * introductory paragraph that mentions one out-of-scope item does not put
 * everything else in that paragraph out of scope too. Every list item under an
 * "Out of Scope" heading is collected whole.
 */
export declare function detectSpecContext(content: string): SpecContext;
/**
 * Why a constraint must not be proposed for this spec, or undefined when it
 * applies. Checked for the mapping first, then for the constraint itself.
 */
export declare function contextSuppressionReason(mapping: CWEMapping, constraint: EARSConstraint, context: SpecContext): string | undefined;
//# sourceMappingURL=spec-context.d.ts.map