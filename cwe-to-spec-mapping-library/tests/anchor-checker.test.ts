import { describe, it, expect } from "vitest";
import {
  checkConstraintAnchoring,
  isInternalEventTrigger,
  isRequestScopedConstraint,
} from "../src/engine/anchor-checker.js";
import type { ProposedRequirement, Requirement } from "../src/types/index.js";

const proposal = (id: string, text: string): ProposedRequirement => ({
  id,
  text,
  earsPattern: "ubiquitous",
  addressesCWEs: ["CWE-862"],
  securityPrimitives: ["ownership-verification"],
  rationale: "test",
  priority: "mandatory",
});

const requirement = (id: string, text: string): Requirement => ({ id, text });

describe("isInternalEventTrigger", () => {
  it("recognises a post-commit event trigger", () => {
    expect(
      isInternalEventTrigger(
        "WHEN the transaction record is successfully written, THE SYSTEM SHALL update the account record."
      )
    ).toBe(true);
  });

  it("does not treat an inbound user request as an internal event", () => {
    expect(
      isInternalEventTrigger(
        "WHEN the user presses Enter on the bill payment screen, THE SYSTEM SHALL process the payment entry."
      )
    ).toBe(false);
  });
});

describe("isRequestScopedConstraint", () => {
  it("recognises request-scoped phrasing", () => {
    expect(
      isRequestScopedConstraint(
        "IF the requesting principal does not own the resource, THEN THE SYSTEM SHALL return HTTP 403."
      )
    ).toBe(true);
  });

  it("does not flag a constraint with no request context", () => {
    expect(
      isRequestScopedConstraint(
        "THE SYSTEM SHALL encrypt sensitive data at rest using AES-256-GCM."
      )
    ).toBe(false);
  });
});

describe("checkConstraintAnchoring", () => {
  it("warns when a request-scoped constraint lands on a post-commit requirement", () => {
    // This is the REQ-F-015 defect: returning 403 after the transaction record is
    // already written leaves the half-applied state the spec's own atomicity
    // requirements forbid.
    const warnings = checkConstraintAnchoring(
      requirement(
        "REQ-F-015b",
        "WHEN the transaction record is successfully written, THE SYSTEM SHALL update the account record."
      ),
      [
        proposal(
          "SEC-1",
          "IF the requesting principal does not own the resource, THEN THE SYSTEM SHALL return HTTP 403 with no data payload."
        ),
      ]
    );

    expect(warnings).toHaveLength(1);
    expect(warnings[0].constraintId).toBe("SEC-1");
    expect(warnings[0].message).toMatch(/partial update/);
  });

  it("stays silent when the requirement is triggered by an inbound request", () => {
    const warnings = checkConstraintAnchoring(
      requirement(
        "REQ-F-002",
        "WHEN the user presses Enter on the bill payment screen, THE SYSTEM SHALL process the payment entry."
      ),
      [
        proposal(
          "SEC-1",
          "IF the requesting principal does not own the resource, THEN THE SYSTEM SHALL return HTTP 403 with no data payload."
        ),
      ]
    );

    expect(warnings).toEqual([]);
  });

  it("does not flag a non-request-scoped constraint on a post-commit requirement", () => {
    const warnings = checkConstraintAnchoring(
      requirement(
        "REQ-F-015b",
        "WHEN the transaction record is successfully written, THE SYSTEM SHALL update the account record."
      ),
      [
        proposal(
          "SEC-1",
          "THE SYSTEM SHALL encrypt sensitive data at rest using AES-256-GCM."
        ),
      ]
    );

    expect(warnings).toEqual([]);
  });

  it("reports without suppressing — anchoring stays the author's decision", () => {
    const proposals = [
      proposal(
        "SEC-1",
        "IF the requesting principal does not own the resource, THEN THE SYSTEM SHALL return HTTP 403 with no data payload."
      ),
    ];
    const warnings = checkConstraintAnchoring(
      requirement(
        "REQ-F-015b",
        "WHEN the transaction record is successfully written, THE SYSTEM SHALL update the account record."
      ),
      proposals
    );

    expect(warnings).toHaveLength(1);
    // The constraint is still present; the checker is advisory only.
    expect(proposals).toHaveLength(1);
  });
});
