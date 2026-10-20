export interface CWEMapping {
    id: string;
    name: string;
    description: string;
    owaspCategory?: string;
    triggerConditions: TriggerCondition[];
    earsConstraints: EARSConstraint[];
    severity: "critical" | "high" | "medium" | "low";
    tags: string[];
    /**
     * Technology the weakness needs before it can exist. When a spec gives no sign
     * of any listed feature — no SQL database for CWE-89, no browser for CWE-79 —
     * the mapping is suppressed for that spec instead of proposing constraints for
     * a component it does not have. Any one listed feature is enough.
     */
    requiresContext?: SpecFeature[];
}
/**
 * Technology a spec can be detected to use. Detected from the whole document
 * (see `detectSpecContext`), not from one requirement: a database named in the
 * introduction makes every search requirement a database query.
 */
export type SpecFeature = "sql-database" | "http" | "html" | "xml" | "ldap";
/** Implementation languages a spec can name, for language-specific examples. */
export type SpecLanguage = "go" | "java" | "python" | "javascript" | "dotnet" | "ruby" | "php";
/**
 * Document-level facts that decide which constraints apply to a spec at all.
 */
export interface SpecContext {
    /** Features the document shows evidence of using. */
    features: SpecFeature[];
    /** Lowercased text of every statement that declares something out of scope. */
    outOfScope: string[];
    /**
     * Implementation languages the spec names. Templates with a language-specific
     * example slot (e.g. `{deserialization_examples}`) cite these languages'
     * APIs; when none is named, a cross-language default is used.
     */
    languages?: SpecLanguage[];
}
export interface TriggerCondition {
    id: string;
    description: string;
    keywords: string[];
    semanticPatterns: string[];
    dataFlowIndicators?: string[];
}
export interface EARSConstraint {
    id: string;
    pattern: EARSPattern;
    template: string;
    securityPrimitive: string;
    rationale: string;
    /**
     * Alternative wordings for specs that have a given feature. The first variant
     * whose feature the spec has replaces `template`; otherwise `template` is
     * used. Keeps the default wording neutral ("outside any directory the system
     * serves files from") while a web spec still gets the precise one ("outside
     * the web-accessible document root").
     */
    variants?: {
        when: SpecFeature;
        template: string;
    }[];
    /** Like `CWEMapping.requiresContext`, for one constraint of a mapping. */
    requiresContext?: SpecFeature[];
    /**
     * Terms that, when a spec declares any of them out of scope ("TLS or other
     * encryption"), suppress this constraint. Proposing TLS for a spec whose
     * authors decided against TLS contradicts the spec rather than hardening it.
     */
    outOfScopeTerms?: string[];
    /**
     * Regex (case-insensitive) the parent requirement must match for this
     * constraint to attach to it. Keeps a storage constraint such as password
     * hashing off a requirement that only prompts for or sends the password.
     */
    appliesTo?: string;
}
export type EARSPattern = "ubiquitous" | "event-driven" | "state-driven" | "optional-feature" | "unwanted-behavior" | "complex";
export interface Requirement {
    id: string;
    text: string;
    earsPattern?: EARSPattern;
    securityAnnotations?: string[];
}
export interface HardeningResult {
    originalRequirement: Requirement;
    triggeredCWEs: TriggeredCWE[];
    proposedRequirements: ProposedRequirement[];
    coverageScore: number;
}
export interface TriggeredCWE {
    cweId: string;
    cweName: string;
    confidence: number;
    matchedTriggers: string[];
    /** Keywords that matched, for judging how strong the evidence is. */
    matchedKeywords?: string[];
    /** Semantic patterns that matched. Empty means keywords alone fired the CWE. */
    matchedPatterns?: string[];
    severity: "critical" | "high" | "medium" | "low";
}
/**
 * A constraint the engine would have proposed but withheld because the spec's
 * context rules it out. Reported so the omission is visible, not silent.
 */
export interface SuppressedConstraint {
    requirementId: string;
    cweId: string;
    constraintId: string;
    reason: string;
}
export interface ProposedRequirement {
    id: string;
    text: string;
    earsPattern: EARSPattern;
    addressesCWEs: string[];
    securityPrimitives: string[];
    rationale: string;
    priority: "mandatory" | "recommended" | "optional";
    /**
     * Placeholders that could not be filled from the requirement and fell back
     * to generic text ("the target", "the operation"). A clause with any is a
     * draft that must be specialized to the requirement before it is useful.
     */
    genericSlots?: {
        slot: string;
        filledWith: string;
    }[];
}
export interface HardeningReport {
    timestamp: string;
    inputRequirements: Requirement[];
    results: HardeningResult[];
    summary: HardeningSummary;
}
/**
 * A CWE the lexical detector saw a *whiff* of — it matched keywords or patterns,
 * but scored below the confidence threshold, so it was dropped from the
 * deterministic output. Object-level authorization gaps (e.g. CWE-862 with no
 * care-relationship check) land here: the phrasing offers one weak lexical
 * signal but the real defect is a *missing* scoping clause, which no `includes()`
 * can see. These candidates are not applied to the file; they are handed to an
 * agent to adjudicate semantically and, if confirmed, specialize to the domain.
 */
export interface SemanticCandidate {
    requirementId: string;
    requirementText: string;
    cweId: string;
    cweName: string;
    severity: "critical" | "high" | "medium" | "low";
    /** Why lexical demoted it: the sub-threshold score and what matched. */
    lexicalConfidence: number;
    matchedTriggers: string[];
    /** Everything an agent needs to adjudicate without re-reading the mappings. */
    reasoning: {
        description: string;
        dataFlowIndicators: string[];
        /** The boundary question the agent should answer for this CWE. */
        adjudicationQuestion: string;
    };
    /** Constraint templates to domain-specialize if the candidate is confirmed. */
    candidateConstraints: {
        id: string;
        template: string;
        securityPrimitive: string;
        rationale: string;
    }[];
}
export interface HardeningSummary {
    totalRequirements: number;
    requirementsWithGaps: number;
    totalCWEsTriggered: number;
    totalProposedAdditions: number;
    criticalGaps: number;
    overallSecurityScore: number;
}
//# sourceMappingURL=index.d.ts.map