export interface CWEMapping {
  id: string;
  name: string;
  description: string;
  owaspCategory?: string;
  triggerConditions: TriggerCondition[];
  earsConstraints: EARSConstraint[];
  severity: "critical" | "high" | "medium" | "low";
  tags: string[];
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
}

export type EARSPattern =
  | "ubiquitous"
  | "event-driven"
  | "state-driven"
  | "optional-feature"
  | "unwanted-behavior"
  | "complex";

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
  severity: "critical" | "high" | "medium" | "low";
}

export interface ProposedRequirement {
  id: string;
  text: string;
  earsPattern: EARSPattern;
  addressesCWEs: string[];
  securityPrimitives: string[];
  rationale: string;
  priority: "mandatory" | "recommended" | "optional";
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
