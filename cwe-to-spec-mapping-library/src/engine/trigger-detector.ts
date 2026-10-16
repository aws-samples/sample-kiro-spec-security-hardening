import type { CWEMapping, Requirement, TriggerCondition, TriggeredCWE } from "../types/index.js";
import { allMappings } from "../mappings/index.js";

export class TriggerDetector {
  private mappings: CWEMapping[];

  constructor(mappings: CWEMapping[] = allMappings) {
    this.mappings = mappings;
  }

  detectTriggers(requirement: Requirement): TriggeredCWE[] {
    const triggered: TriggeredCWE[] = [];
    const normalizedText = requirement.text.toLowerCase();

    for (const mapping of this.mappings) {
      const matchResult = this.evaluateMapping(normalizedText, mapping);
      if (matchResult.confidence > 0) {
        triggered.push({
          cweId: mapping.id,
          cweName: mapping.name,
          confidence: matchResult.confidence,
          matchedTriggers: matchResult.matchedTriggers,
          severity: mapping.severity,
        });
      }
    }

    return triggered.sort((a, b) => {
      const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
      const severityDiff = severityOrder[b.severity] - severityOrder[a.severity];
      if (severityDiff !== 0) return severityDiff;
      return b.confidence - a.confidence;
    });
  }

  private evaluateMapping(
    text: string,
    mapping: CWEMapping
  ): { confidence: number; matchedTriggers: string[] } {
    let maxScore = 0;
    const matchedTriggers: string[] = [];

    for (const trigger of mapping.triggerConditions) {
      const triggerScore = this.evaluateTrigger(text, trigger);
      if (triggerScore > 0) {
        matchedTriggers.push(trigger.description);
        if (triggerScore > maxScore) {
          maxScore = triggerScore;
        }
      }
    }

    return { confidence: Math.min(maxScore, 1.0), matchedTriggers };
  }

  private evaluateTrigger(text: string, trigger: TriggerCondition): number {
    const keywordHits = this.countKeywordHits(text, trigger.keywords);
    const patternHits = this.countPatternHits(text, trigger.semanticPatterns);

    if (keywordHits === 0 && patternHits === 0) return 0;

    // Keywords are alternative indicators — 2+ hits is strong signal
    const keywordScore = keywordHits >= 3 ? 1.0 : keywordHits >= 2 ? 0.7 : keywordHits >= 1 ? 0.4 : 0;

    // Patterns are semantic matches — any hit is strong
    const patternScore = patternHits >= 2 ? 1.0 : patternHits >= 1 ? 0.7 : 0;

    // Combine: either signal alone can produce high confidence
    return Math.min(keywordScore * 0.4 + patternScore * 0.6, 1.0);
  }

  private countKeywordHits(text: string, keywords: string[]): number {
    if (keywords.length === 0) return 0;
    return keywords.filter((kw) => text.includes(kw.toLowerCase())).length;
  }

  private countPatternHits(text: string, patterns: string[]): number {
    if (patterns.length === 0) return 0;
    let matchCount = 0;

    for (const pattern of patterns) {
      try {
        const regex = new RegExp(pattern, "i");
        if (regex.test(text)) {
          matchCount++;
        }
      } catch {
        if (text.includes(pattern.toLowerCase())) {
          matchCount++;
        }
      }
    }

    return matchCount;
  }
}
