import type { EARSConstraint, SpecContext } from "../types/index.js";
export interface FilledTemplate {
    text: string;
    /** Slots filled with generic text that the reader must specialize. */
    genericSlots: {
        slot: string;
        filledWith: string;
    }[];
}
/**
 * The wording of a constraint for a spec: the first variant whose feature the
 * spec has, else the default template, with example slots resolved.
 */
export declare function resolveTemplate(constraint: EARSConstraint, context?: SpecContext): string;
/**
 * Fills a template's `{placeholder}` slots from the requirement text.
 *
 * Extraction is conservative: a slot is filled only when the candidate phrase
 * is verified to fit that position. A doubtful extraction is declined in favour
 * of the generic fallback, which is always grammatical, and the fallback is
 * reported in `genericSlots`.
 */
export declare function fillTemplate(template: string, requirementText?: string): FilledTemplate;
//# sourceMappingURL=template-filler.d.ts.map