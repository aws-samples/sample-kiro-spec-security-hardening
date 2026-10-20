import type { ProposedRequirement, Requirement, TriggeredCWE } from "../types/index.js";

/**
 * Flags security constraints attached to the wrong point in a flow.
 *
 * A constraint phrased around an inbound request ("the requesting principal",
 * "return HTTP 403") is only meaningful where a request is being admitted. Attach
 * it to a requirement whose trigger is an internal, post-commit event and it
 * becomes both untestable and unsafe:
 *
 *   REQ-F-015: WHEN the transaction record is successfully written, THE SYSTEM
 *              SHALL update the account record.
 *     - IF the requesting principal does not own the resource, THEN THE SYSTEM
 *       SHALL return HTTP 403 with no data payload.
 *
 * At that point the request was already authorized upstream and the transaction
 * record is already committed, so "return 403 and skip the update" produces
 * exactly the half-applied state the spec's own atomicity requirements forbid.
 *
 * A second, more common misplacement is a CWE that fired on loose keywords
 * alone. "WHEN the user enters `/quit` ..., THE Chat_Client SHALL send a logout
 * request" contains "input", "enter" and "request", which is enough for input
 * validation to fire, yet the requirement handles no untrusted input. No
 * semantic pattern of the CWE matched, so the placement is reported for review.
 *
 * This module only reports. Moving a constraint to the right requirement changes
 * which obligation the spec places where, which is an author's decision rather
 * than something a formatter should silently do.
 */

/** Phrasing that presumes an inbound, not-yet-authorized request. */
const REQUEST_SCOPED = [
  /\brequesting principal\b/i,
  /\bHTTP 40[13]\b/i,
  /\bauthorization error\b/i,
  /\bauthenticated caller\b/i,
  /\bCSRF token\b/i,
  /\bthe request\b/i,
];

/**
 * Triggers naming an internal event that occurs after a request is admitted.
 *
 * The `successfully` / `is written` / `has been` forms are the reliable marker:
 * they describe an outcome the system produced, not an input it received.
 */
const INTERNAL_EVENT = [
  /\bWHEN\b[^,]*\b(?:record|transaction|write|update|balance)\b[^,]*\bis\s+(?:successfully\s+)?(?:written|created|updated|committed|persisted)\b/i,
  /\bWHEN\b[^,]*\bhas\s+been\s+(?:written|computed|created|updated|committed|persisted)\b/i,
  /\bWHEN\b[^,]*\b(?:write|update|transaction)\b[^,]*\bsucceeds?\b/i,
  /\bWHEN\b[^,]*\bsuccessfully\s+(?:written|created|updated|committed|persisted)\b/i,
];

export interface AnchorWarning {
  requirementId: string;
  constraintId: string;
  message: string;
}

/** True when the requirement's trigger names an internal post-commit event. */
export function isInternalEventTrigger(text: string): boolean {
  return INTERNAL_EVENT.some((pattern) => pattern.test(text));
}

/** True when the constraint presumes an inbound request context. */
export function isRequestScopedConstraint(text: string): boolean {
  return REQUEST_SCOPED.some((pattern) => pattern.test(text));
}

/**
 * Reports request-scoped constraints anchored to internal-event requirements.
 *
 * Returns an empty array for the common case, so a caller can treat a non-empty
 * result as "this spec needs an author's attention".
 */
export function checkConstraintAnchoring(
  requirement: Requirement,
  proposals: ProposedRequirement[],
  triggered: TriggeredCWE[] = []
): AnchorWarning[] {
  return [
    ...checkInternalEventAnchoring(requirement, proposals),
    ...checkKeywordOnlyAnchoring(requirement, proposals, triggered),
  ];
}

/**
 * Reports proposals whose CWE matched only on keywords, with no semantic
 * pattern. One warning per CWE, naming every constraint it produced.
 */
function checkKeywordOnlyAnchoring(
  requirement: Requirement,
  proposals: ProposedRequirement[],
  triggered: TriggeredCWE[]
): AnchorWarning[] {
  const warnings: AnchorWarning[] = [];
  for (const cwe of triggered) {
    if (!cwe.matchedPatterns || cwe.matchedPatterns.length > 0) continue;
    const ids = proposals
      .filter((proposal) => proposal.addressesCWEs.includes(cwe.cweId))
      .map((proposal) => proposal.id);
    if (ids.length === 0) continue;
    warnings.push({
      requirementId: requirement.id,
      constraintId: ids.join(", "),
      message:
        `${cwe.cweId} matched ${requirement.id} only on the keywords ` +
        `${(cwe.matchedKeywords ?? []).map((k) => `"${k}"`).join(", ")}, with no ` +
        `pattern of the weakness — confirm the requirement actually handles it, ` +
        `or move or drop the constraint`,
    });
  }
  return warnings;
}

function checkInternalEventAnchoring(
  requirement: Requirement,
  proposals: ProposedRequirement[]
): AnchorWarning[] {
  if (!isInternalEventTrigger(requirement.text)) return [];

  return proposals
    .filter((proposal) => isRequestScopedConstraint(proposal.text))
    .map((proposal) => ({
      requirementId: requirement.id,
      constraintId: proposal.id,
      message:
        `constraint is request-scoped but ${requirement.id} is triggered by an internal ` +
        `post-commit event; enforcing it here cannot reject the request and may leave a ` +
        `partial update — anchor it to the request-entry requirement instead`,
    }));
}
