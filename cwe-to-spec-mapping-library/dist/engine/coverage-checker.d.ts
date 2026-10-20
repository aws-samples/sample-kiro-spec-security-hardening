import type { Requirement, TriggeredCWE, CWEMapping } from "../types/index.js";
export declare class CoverageChecker {
    private mappings;
    constructor(mappings?: CWEMapping[]);
    checkCoverage(requirements: Requirement[], triggeredCWEs: TriggeredCWE[]): CoverageGap[];
    private isConstraintCovered;
    private extractCoverageIndicators;
    private extractFromTemplate;
}
export interface CoverageGap {
    cweId: string;
    cweName: string;
    severity: "critical" | "high" | "medium" | "low";
    missingPrimitive: string;
    constraintId: string;
    suggestedTemplate: string;
    rationale: string;
}
//# sourceMappingURL=coverage-checker.d.ts.map