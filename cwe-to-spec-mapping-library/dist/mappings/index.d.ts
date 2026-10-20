import type { CWEMapping } from "../types/index.js";
import { injectionMappings } from "./injection.js";
import { authenticationMappings } from "./authentication.js";
import { authorizationMappings } from "./authorization.js";
import { dataExposureMappings } from "./data-exposure.js";
import { cryptographyMappings } from "./cryptography.js";
import { inputValidationMappings } from "./input-validation.js";
import { securityMisconfigurationMappings } from "./security-misconfiguration.js";
import { businessLogicMappings } from "./business-logic.js";
export declare const allMappings: CWEMapping[];
export declare function getMappingById(cweId: string): CWEMapping | undefined;
export declare function getMappingsByTag(tag: string): CWEMapping[];
export declare function getMappingsByOwasp(category: string): CWEMapping[];
export declare function getMappingsBySeverity(severity: CWEMapping["severity"]): CWEMapping[];
export { injectionMappings, authenticationMappings, authorizationMappings, dataExposureMappings, cryptographyMappings, inputValidationMappings, securityMisconfigurationMappings, businessLogicMappings, };
//# sourceMappingURL=index.d.ts.map