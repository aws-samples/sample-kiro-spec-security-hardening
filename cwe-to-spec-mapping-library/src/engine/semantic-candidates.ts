import type {
  CWEMapping,
  Requirement,
  SemanticCandidate,
  TriggeredCWE,
} from "../types/index.js";

/**
 * Lexical scores below the confidence threshold but above this floor are treated
 * as "whiffs" — one weak signal worth an agent's second look — rather than noise.
 * The lowest score the detector can emit for a single keyword hit is 0.16, so a
 * floor of 0.05 keeps that band while discarding the truly incidental.
 */
export const DEFAULT_SEMANTIC_CANDIDATE_FLOOR = 0.05;

/** Cap on candidates surfaced per requirement, so a broad sweep cannot flood. */
export const DEFAULT_MAX_SEMANTIC_CANDIDATES = 8;

/**
 * Which classes of sub-threshold CWE to surface.
 *
 * `authz` (default) restricts to *object-level authorization*: the class where a
 * weak lexical hit genuinely signals a defect, because the vulnerability is a
 * missing relationship predicate between caller and resource, not a keyword.
 * Widening the confidence threshold would never recover these correctly, and
 * they are indistinguishable — lexically — from incidental keyword matches, so
 * an agent must adjudicate them. `all` additionally surfaces every other
 * sub-threshold hit for a thorough manual sweep, at the cost of noise.
 */
export type SemanticCandidateScope = "authz" | "all";

/**
 * Tags that mark a mapping as an *object-level* authorization concern — one
 * scoped to a specific resource instance, where the defect is typically an absent
 * relationship predicate between caller and resource. Deliberately excludes the
 * broad "authorization" tag (which also covers vertical privilege escalation such
 * as CWE-269, a different problem) so the default scope stays tight.
 */
const OBJECT_LEVEL_AUTHZ_TAGS = new Set([
  "access-control",
  "ownership-verification",
  "idor",
  "multi-tenant",
  "user-controlled-key",
]);

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1 } as const;

function isObjectLevelAuthz(mapping: CWEMapping): boolean {
  return mapping.tags.some((t) => OBJECT_LEVEL_AUTHZ_TAGS.has(t));
}

/**
 * Builds the question an agent should answer to confirm or dismiss a candidate.
 *
 * For object-level authorization CWEs the question drives at the specific gap the
 * lexical detector misses: a requirement may name a caller and a resource yet
 * never constrain the *relationship* between them ("any clinician can read any
 * patient's notes"). For other CWEs it falls back to a generic exposure question
 * grounded in the mapping's own description.
 */
function adjudicationQuestion(mapping: CWEMapping): string {
  if (isObjectLevelAuthz(mapping)) {
    return (
      `Does this requirement constrain the relationship between the requesting ` +
      `principal and the specific resource it accesses (ownership, tenancy, or an ` +
      `explicit relationship such as an active care relationship)? If the caller ` +
      `can reach any instance of the resource without such a predicate, ${mapping.id} ` +
      `applies — specialize the constraint below to name the domain relationship, ` +
      `not a generic "resource owner".`
    );
  }

  return (
    `Given "${mapping.description}", does this requirement actually expose ${mapping.id}? ` +
    `Confirm from the requirement's semantics rather than keyword presence, then ` +
    `specialize the constraint below to this requirement's domain before applying it.`
  );
}

export interface SemanticCandidateOptions {
  scope?: SemanticCandidateScope;
  floor?: number;
  threshold?: number;
  maxPerRequirement?: number;
}

/**
 * Collects the sub-threshold CWEs for one requirement as semantic candidates.
 *
 * `triggered` is the *unfiltered* detector output; `promotedCweIds` are the CWEs
 * that cleared the threshold and are already handled deterministically, so they
 * are excluded here to avoid proposing the same constraint twice. Results are
 * ordered most-relevant-first (object-level authz, then severity, then
 * confidence) and capped so a broad sweep cannot bury the signal.
 */
export function collectSemanticCandidates(
  requirement: Requirement,
  triggered: TriggeredCWE[],
  mappings: CWEMapping[],
  promotedCweIds: Set<string>,
  options: SemanticCandidateOptions = {}
): SemanticCandidate[] {
  const scope = options.scope ?? "authz";
  const floor = options.floor ?? DEFAULT_SEMANTIC_CANDIDATE_FLOOR;
  const threshold = options.threshold ?? 0.3;
  const maxPerRequirement =
    options.maxPerRequirement ?? DEFAULT_MAX_SEMANTIC_CANDIDATES;

  const scored: { candidate: SemanticCandidate; mapping: CWEMapping }[] = [];

  for (const t of triggered) {
    if (promotedCweIds.has(t.cweId)) continue;
    if (t.confidence <= floor || t.confidence >= threshold) continue;

    const mapping = mappings.find((m) => m.id === t.cweId);
    if (!mapping) continue;
    if (scope === "authz" && !isObjectLevelAuthz(mapping)) continue;

    const dataFlowIndicators = mapping.triggerConditions.flatMap(
      (tc) => tc.dataFlowIndicators ?? []
    );

    scored.push({
      mapping,
      candidate: {
        requirementId: requirement.id,
        requirementText: requirement.text,
        cweId: mapping.id,
        cweName: mapping.name,
        severity: mapping.severity,
        lexicalConfidence: t.confidence,
        matchedTriggers: t.matchedTriggers,
        reasoning: {
          description: mapping.description,
          dataFlowIndicators,
          adjudicationQuestion: adjudicationQuestion(mapping),
        },
        candidateConstraints: mapping.earsConstraints.map((c) => ({
          id: c.id,
          template: c.template,
          securityPrimitive: c.securityPrimitive,
          rationale: c.rationale,
        })),
      },
    });
  }

  scored.sort((a, b) => {
    const authzDiff =
      Number(isObjectLevelAuthz(b.mapping)) -
      Number(isObjectLevelAuthz(a.mapping));
    if (authzDiff !== 0) return authzDiff;
    const sevDiff =
      SEVERITY_ORDER[b.candidate.severity] - SEVERITY_ORDER[a.candidate.severity];
    if (sevDiff !== 0) return sevDiff;
    return b.candidate.lexicalConfidence - a.candidate.lexicalConfidence;
  });

  return scored.slice(0, maxPerRequirement).map((s) => s.candidate);
}
