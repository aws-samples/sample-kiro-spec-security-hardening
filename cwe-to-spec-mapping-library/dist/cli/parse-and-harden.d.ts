import type { HardeningOptions } from "../engine/hardening-engine.js";
import type { AnchorWarning } from "../engine/anchor-checker.js";
import { type SourceWarning } from "../engine/source-normalizer.js";
import type { EARSPattern, HardeningReport, SemanticCandidate, SuppressedConstraint } from "../types/index.js";
export interface ParsedRequirement {
    id: string;
    text: string;
    /**
     * The requirement as written, with the list marker and `[SECURITY: ...]` tag
     * removed but its `REQ-x:` prefix and `[Pattern]` tag intact.
     */
    rawText: string;
    earsPattern: EARSPattern;
    /** Primitives named by a leading `[SECURITY: ...]` tag, if present. */
    securityAnnotations?: string[];
    /**
     * True for a `[SECURITY: ...]` constraint line — one this tool or a reviewer
     * added earlier. Constraints count toward coverage but are never hardened
     * themselves.
     */
    constraint?: boolean;
    /**
     * How a person finds the requirement: `12.3` for criterion 3 under
     * "Requirement 12", the author's own ID such as `REQ-F-015`, or `line 40`.
     */
    label: string;
    /** The "Requirement N" section the line sits in, when there is one. */
    section?: string;
    /** True for a line inside the Security Baseline section. */
    inBaseline?: boolean;
    /** Index of the first line of this requirement in the source file. */
    lineStart: number;
    /** Index of the last line of this requirement in the source file. */
    lineEnd: number;
    /** Leading whitespace of the requirement's first line. */
    indent: string;
    /** True when the requirement is written as a markdown ordered-list item. */
    numbered: boolean;
}
/** One line hardening adds, located by the original line it follows. */
export interface AddedLine {
    /** 1-based line of the original file the addition follows (0 = file start). */
    after: number;
    text: string;
}
export type HardenMode = 
/** First run: every requirement was hardened. */
"full"
/** Hardened before: only requirements added or changed since were hardened. */
 | "incremental"
/** Hardened before and nothing has changed since. File left untouched. */
 | "up-to-date"
/** Hardened by an older version with no review record. File left untouched. */
 | "unrecorded"
/** `markReviewed`: the current requirements were recorded as reviewed. */
 | "marked"
/** `check`: the file was validated only. Nothing was proposed or written. */
 | "checked";
export interface HardenFileOptions extends HardeningOptions {
    /** Compute and report the additions without writing the file. */
    dryRun?: boolean;
    /**
     * Record every current requirement as reviewed without proposing anything.
     * Use on a file hardened by an older version (mode `unrecorded`) so later
     * runs harden only what is added afterwards.
     */
    markReviewed?: boolean;
    /**
     * Validate only: report requirements that are not strict EARS and
     * `[SECURITY: ...]` lines that are malformed, and write nothing. Use after
     * hand-editing constraints.
     */
    check?: boolean;
}
/** A problem with a `[SECURITY: ...]` line already in the file, or one just added. */
export interface ConstraintWarning {
    /** `12.3 (line 40)` for an inline constraint, `line 300` for a baseline one. */
    location: string;
    /** The line's constraint ID, or `(no ID)`. */
    constraintId: string;
    message: string;
}
export interface HardenFileResult {
    inputPath: string;
    /** Always equal to `inputPath`: hardening edits the file in place. */
    outputPath: string;
    /** Source requirements found, not counting `[SECURITY: ...]` lines. */
    requirementsFound: number;
    /** Requirements this run hardened (all on a first run, new ones afterwards). */
    requirementsHardened: number;
    /** Cross-cutting constraints this run added to the Security Baseline. */
    baselineConstraints: number;
    /** Stale sidecar artifacts from an older two-file run that were removed. */
    removedArtifacts: string[];
    mode: HardenMode;
    /** True when the file was left untouched (`up-to-date` or `unrecorded`). */
    skipped: boolean;
    /** True when `dryRun` was set: `addedLines` were computed but not written. */
    dryRun: boolean;
    /** Every line this run adds. Original lines are never changed or removed. */
    addedLines: AddedLine[];
    report: HardeningReport;
    /** Source requirements that are not strict EARS. Reported, never rewritten. */
    sourceWarnings: SourceWarning[];
    /** Constraints that may be anchored to the wrong requirement. */
    anchorWarnings: AnchorWarning[];
    /** Constraints withheld because the spec's context rules them out. */
    suppressedConstraints: SuppressedConstraint[];
    /**
     * Added constraints built with generic placeholder text ("the target", "the
     * operation") because the requirement did not supply a value. Each is a
     * draft that must be specialized.
     */
    specializationWarnings: ConstraintWarning[];
    /**
     * Problems in the `[SECURITY: ...]` lines already in the file — including
     * ones a reviewer wrote by hand: two obligations on one line, no named
     * actor, a malformed trigger, a missing or duplicated constraint ID.
     */
    constraintWarnings: ConstraintWarning[];
    /**
     * Proposed constraints not written because the same clause was already
     * being added under an earlier criterion of the same requirement section.
     */
    foldedDuplicates: number;
    /**
     * Sub-threshold CWEs surfaced for agentic adjudication rather than applied to
     * the file (see the harden-spec skill).
     */
    semanticCandidates: SemanticCandidate[];
}
export declare function parseRequirementsFromMarkdown(content: string, filePath: string): ParsedRequirement[];
export declare function hardenMarkdownFile(filePath: string, options?: HardenFileOptions): Promise<HardenFileResult | null>;
export declare function hardenMarkdownFiles(inputs: string[], options?: HardenFileOptions): Promise<HardenFileResult[]>;
//# sourceMappingURL=parse-and-harden.d.ts.map