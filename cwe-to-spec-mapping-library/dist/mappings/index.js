import { injectionMappings } from "./injection.js";
import { authenticationMappings } from "./authentication.js";
import { authorizationMappings } from "./authorization.js";
import { dataExposureMappings } from "./data-exposure.js";
import { cryptographyMappings } from "./cryptography.js";
import { inputValidationMappings } from "./input-validation.js";
import { securityMisconfigurationMappings } from "./security-misconfiguration.js";
import { businessLogicMappings } from "./business-logic.js";
export const allMappings = [
    ...injectionMappings,
    ...authenticationMappings,
    ...authorizationMappings,
    ...dataExposureMappings,
    ...cryptographyMappings,
    ...inputValidationMappings,
    ...securityMisconfigurationMappings,
    ...businessLogicMappings,
];
export function getMappingById(cweId) {
    return allMappings.find((m) => m.id === cweId);
}
export function getMappingsByTag(tag) {
    return allMappings.filter((m) => m.tags.includes(tag));
}
export function getMappingsByOwasp(category) {
    return allMappings.filter((m) => m.owaspCategory === category);
}
export function getMappingsBySeverity(severity) {
    return allMappings.filter((m) => m.severity === severity);
}
export { injectionMappings, authenticationMappings, authorizationMappings, dataExposureMappings, cryptographyMappings, inputValidationMappings, securityMisconfigurationMappings, businessLogicMappings, };
//# sourceMappingURL=index.js.map