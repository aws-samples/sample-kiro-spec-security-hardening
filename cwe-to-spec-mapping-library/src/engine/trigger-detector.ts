import type { CWEMapping, Requirement, TriggeredCWE } from "../types/index.js";
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
          matchedKeywords: matchResult.matchedKeywords,
          matchedPatterns: matchResult.matchedPatterns,
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
  ): {
    confidence: number;
    matchedTriggers: string[];
    matchedKeywords: string[];
    matchedPatterns: string[];
  } {
    let maxScore = 0;
    const matchedTriggers: string[] = [];
    const matchedKeywords = new Set<string>();
    const matchedPatterns = new Set<string>();

    for (const trigger of mapping.triggerConditions) {
      const keywords = this.matchKeywords(text, trigger.keywords);
      const patterns = this.matchPatterns(text, trigger.semanticPatterns);
      const triggerScore = this.scoreTrigger(keywords.length, patterns.length);
      if (triggerScore > 0) {
        matchedTriggers.push(trigger.description);
        keywords.forEach((k) => matchedKeywords.add(k));
        patterns.forEach((p) => matchedPatterns.add(p));
        if (triggerScore > maxScore) {
          maxScore = triggerScore;
        }
      }
    }

    return {
      confidence: Math.min(maxScore, 1.0),
      matchedTriggers,
      matchedKeywords: [...matchedKeywords],
      matchedPatterns: [...matchedPatterns],
    };
  }

  private scoreTrigger(keywordHits: number, patternHits: number): number {
    if (keywordHits === 0 && patternHits === 0) return 0;

    // Keywords are alternative indicators — 2+ hits is strong signal
    const keywordScore = keywordHits >= 3 ? 1.0 : keywordHits >= 2 ? 0.7 : keywordHits >= 1 ? 0.4 : 0;

    // Patterns are semantic matches — any hit is strong
    const patternScore = patternHits >= 2 ? 1.0 : patternHits >= 1 ? 0.7 : 0;

    // Combine: either signal alone can produce high confidence
    return Math.min(keywordScore * 0.4 + patternScore * 0.6, 1.0);
  }

  private matchKeywords(text: string, keywords: string[]): string[] {
    return keywords.filter((kw) => compileKeyword(kw).test(text));
  }

  private matchPatterns(text: string, patterns: string[]): string[] {
    return patterns.filter((pattern) => {
      try {
        return compilePattern(pattern).test(text);
      } catch {
        return compileKeyword(pattern).test(text);
      }
    });
  }
}

/**
 * Inflections a keyword or pattern word may carry and still count as a match:
 * "log" matches "logs" and "logged", "request" matches "requests".
 */
const INFLECTION = "(?:s|es|ed|d|ing)?";

const compiled = new Map<string, RegExp>();

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * A keyword matches whole words only. Substring matching made "log" fire on
 * "logout", "id" on "invalid" and "enter" on "center", which attached
 * logging, IDOR and input constraints to requirements about none of them.
 */
function compileKeyword(keyword: string): RegExp {
  const key = `k:${keyword}`;
  let regex = compiled.get(key);
  if (!regex) {
    regex = new RegExp(`\\b${escapeRegExp(keyword.toLowerCase())}${INFLECTION}\\b`, "i");
    compiled.set(key, regex);
  }
  return regex;
}

/**
 * Compiles a semantic pattern so that each literal segment between `.*` gaps
 * matches on word boundaries. Without them "log.*request" matched "logout
 * request" and "register.*user" matched "register <username>".
 */
function compilePattern(pattern: string): RegExp {
  const key = `p:${pattern}`;
  let regex = compiled.get(key);
  if (!regex) {
    const source = pattern
      .split(".*")
      .map((segment) => {
        const start = /^[\w(]/.test(segment) ? "\\b" : "";
        const end = /[\w)]$/.test(segment) ? `${INFLECTION}\\b` : "";
        return `${start}${segment}${end}`;
      })
      .join(".*");
    regex = new RegExp(source, "i");
    compiled.set(key, regex);
  }
  return regex;
}
