import type { CWEMapping } from "../types/index.js";
import { injectionMappings } from "./injection.js";
import { authenticationMappings } from "./authentication.js";
import { authorizationMappings } from "./authorization.js";
import { dataExposureMappings } from "./data-exposure.js";
import { cryptographyMappings } from "./cryptography.js";
import { inputValidationMappings } from "./input-validation.js";
import { securityMisconfigurationMappings } from "./security-misconfiguration.js";
import { businessLogicMappings } from "./business-logic.js";

export const allMappings: CWEMapping[] = [
  ...injectionMappings,
  ...authenticationMappings,
  ...authorizationMappings,
  ...dataExposureMappings,
  ...cryptographyMappings,
  ...inputValidationMappings,
  ...securityMisconfigurationMappings,
  ...businessLogicMappings,
];

export function getMappingById(cweId: string): CWEMapping | undefined {
  return allMappings.find((m) => m.id === cweId);
}

export function getMappingsByTag(tag: string): CWEMapping[] {
  return allMappings.filter((m) => m.tags.includes(tag));
}

export function getMappingsByOwasp(category: string): CWEMapping[] {
  return allMappings.filter((m) => m.owaspCategory === category);
}

export function getMappingsBySeverity(severity: CWEMapping["severity"]): CWEMapping[] {
  return allMappings.filter((m) => m.severity === severity);
}

export {
  injectionMappings,
  authenticationMappings,
  authorizationMappings,
  dataExposureMappings,
  cryptographyMappings,
  inputValidationMappings,
  securityMisconfigurationMappings,
  businessLogicMappings,
};
