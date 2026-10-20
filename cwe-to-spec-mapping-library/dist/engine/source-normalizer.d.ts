import type { EARSPattern } from "../types/index.js";
export interface SourceWarning {
    requirementId: string;
    message: string;
}
export interface NormalizedRequirement {
    /** Suffixed when the source requirement split; otherwise the original ID. */
    id: string;
    /** The original, unsuffixed source ID — the traceability key. */
    sourceId: string;
    /** Strict-EARS requirement text, without the ID prefix or pattern tag. */
    text: string;
    /** Full rendered line: `<id>: [<Pattern>] <text>`. */
    rendered: string;
    earsPattern: EARSPattern;
    /** True when this requirement is one part of a split compound. */
    split: boolean;
}
export interface SourceNormalizationResult {
    requirements: NormalizedRequirement[];
    warnings: SourceWarning[];
}
/**
 * Checks one source requirement against the EARS grammar without changing it.
 *
 * Returns the problems a human must fix — no SHALL, no named actor, an `IF`
 * without `THEN`, an unclosed precondition, a passive obligation. `line` may
 * carry a `REQ-x:` prefix and a `[Pattern]` tag; both are ignored.
 */
export declare function validateSourceRequirement(line: string): {
    valid: boolean;
    pattern?: EARSPattern;
    errors: string[];
};
/**
 * Checks one `[SECURITY: ...]` constraint statement — tag and ID removed — as
 * strictly as a generated one: one obligation per line, a named actor, a
 * well-formed trigger. Constraints are what a coding agent implements one by
 * one, so "SHALL scope X AND SHALL NOT grant Y" is reported as two
 * obligations even though a hand-written source requirement may join them.
 */
export declare function validateConstraintStatement(text: string): {
    valid: boolean;
    errors: string[];
};
/**
 * Normalizes one source requirement line into one or more strict-EARS
 * requirements.
 *
 * `line` is the requirement text as written, including its `REQ-x:` prefix and
 * any `[Pattern]` annotation. Both are stripped, the body is normalized, and the
 * prefix is rebuilt from the pattern actually detected — a source tagged
 * `[Event-driven]` whose text is ubiquitous gets a corrected tag rather than the
 * one it claimed.
 */
export declare function normalizeSourceRequirement(line: string): SourceNormalizationResult;
//# sourceMappingURL=source-normalizer.d.ts.map