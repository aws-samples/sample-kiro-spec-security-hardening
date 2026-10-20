export { detectSpecContext, contextSuppressionReason } from "./engine/spec-context.js";
export { HardeningEngine, formatAsSecurityAnnotatedEARS } from "./engine/hardening-engine.js";
export { atomizeTemplate, classifyEARSPattern, hoistEmbeddedPrecondition, isHoistableEvent, isValidActorPhrase, normalizeEARSClause, toValidEARSClauses, validateEARSClause, } from "./engine/ears-normalizer.js";
export { normalizeSourceRequirement, validateConstraintStatement, validateSourceRequirement, } from "./engine/source-normalizer.js";
export { fillTemplate, resolveTemplate } from "./engine/template-filler.js";
export { checkConstraintAnchoring, isInternalEventTrigger, isRequestScopedConstraint, } from "./engine/anchor-checker.js";
export { TriggerDetector } from "./engine/trigger-detector.js";
export { collectSemanticCandidates, DEFAULT_SEMANTIC_CANDIDATE_FLOOR, DEFAULT_MAX_SEMANTIC_CANDIDATES, } from "./engine/semantic-candidates.js";
export { CoverageChecker } from "./engine/coverage-checker.js";
export { parseRequirementsFromMarkdown, hardenMarkdownFile, hardenMarkdownFiles, } from "./cli/parse-and-harden.js";
export { allMappings, getMappingById, getMappingsByTag, getMappingsByOwasp, getMappingsBySeverity, injectionMappings, authenticationMappings, authorizationMappings, dataExposureMappings, cryptographyMappings, inputValidationMappings, securityMisconfigurationMappings, businessLogicMappings, } from "./mappings/index.js";
//# sourceMappingURL=index.js.map