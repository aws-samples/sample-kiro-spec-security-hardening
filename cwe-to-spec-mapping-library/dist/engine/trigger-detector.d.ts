import type { CWEMapping, Requirement, TriggeredCWE } from "../types/index.js";
export declare class TriggerDetector {
    private mappings;
    constructor(mappings?: CWEMapping[]);
    detectTriggers(requirement: Requirement): TriggeredCWE[];
    private evaluateMapping;
    private scoreTrigger;
    private matchKeywords;
    private matchPatterns;
}
//# sourceMappingURL=trigger-detector.d.ts.map