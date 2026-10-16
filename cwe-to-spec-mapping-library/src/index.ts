export type {
  CWEMapping,
  TriggerCondition,
  EARSConstraint,
  EARSPattern,
  Requirement,
  HardeningResult,
  TriggeredCWE,
  ProposedRequirement,
  HardeningReport,
  HardeningSummary,
  SemanticCandidate,
} from "./types/index.js";

export { HardeningEngine, formatAsSecurityAnnotatedEARS } from "./engine/hardening-engine.js";
export type { HardeningOptions, RejectedClause } from "./engine/hardening-engine.js";

export {
  atomizeTemplate,
  classifyEARSPattern,
  hoistEmbeddedPrecondition,
  isValidActorPhrase,
  normalizeEARSClause,
  toValidEARSClauses,
  validateEARSClause,
} from "./engine/ears-normalizer.js";
export type { EARSValidationResult } from "./engine/ears-normalizer.js";

export { normalizeSourceRequirement } from "./engine/source-normalizer.js";
export type {
  NormalizedRequirement,
  SourceNormalizationResult,
  SourceWarning,
} from "./engine/source-normalizer.js";

export {
  checkConstraintAnchoring,
  isInternalEventTrigger,
  isRequestScopedConstraint,
} from "./engine/anchor-checker.js";
export type { AnchorWarning } from "./engine/anchor-checker.js";
export { TriggerDetector } from "./engine/trigger-detector.js";
export {
  collectSemanticCandidates,
  DEFAULT_SEMANTIC_CANDIDATE_FLOOR,
  DEFAULT_MAX_SEMANTIC_CANDIDATES,
} from "./engine/semantic-candidates.js";
export type {
  SemanticCandidateScope,
  SemanticCandidateOptions,
} from "./engine/semantic-candidates.js";
export { CoverageChecker } from "./engine/coverage-checker.js";
export type { CoverageGap } from "./engine/coverage-checker.js";

export {
  parseRequirementsFromMarkdown,
  hardenMarkdownFile,
  hardenMarkdownFiles,
} from "./cli/parse-and-harden.js";

export {
  allMappings,
  getMappingById,
  getMappingsByTag,
  getMappingsByOwasp,
  getMappingsBySeverity,
  injectionMappings,
  authenticationMappings,
  authorizationMappings,
  dataExposureMappings,
  cryptographyMappings,
  inputValidationMappings,
  securityMisconfigurationMappings,
  businessLogicMappings,
} from "./mappings/index.js";
