import { describe, it, expect } from "vitest";
import { normalizeSourceRequirement } from "../src/engine/source-normalizer.js";
import { validateEARSClause } from "../src/engine/ears-normalizer.js";

/** The requirement that motivated strict source normalization. */
const REQ_F_015 =
  "REQ-F-015: [Event-driven] When the transaction record is successfully written, " +
  "the system shall compute the new account balance by subtracting the payment " +
  "amount from the current balance and update the account record in the account " +
  "keyed dataset (legacy: AWS.M2.CARDDEMO.ACCTDATA.VSAM.KSDS).";

describe("normalizeSourceRequirement", () => {
  it("splits REQ-F-015's compound response into suffixed atomic requirements", () => {
    const { requirements } = normalizeSourceRequirement(REQ_F_015);

    expect(requirements.map((r) => r.id)).toEqual(["REQ-F-015a", "REQ-F-015b"]);
    expect(requirements[0].text).toContain("compute the new account balance");
    expect(requirements[0].text).not.toContain("update the account record");
    expect(requirements[1].text).toContain("update the account record");
  });

  it("propagates the trigger onto every part of a split", () => {
    const { requirements } = normalizeSourceRequirement(REQ_F_015);

    // Dropping the trigger would widen the second obligation from "only after
    // the write succeeds" to "at all times".
    for (const requirement of requirements) {
      expect(requirement.text).toMatch(
        /^WHEN the transaction record is successfully written,/
      );
    }
  });

  it("keeps the original ID resolvable as a prefix for traceability", () => {
    const { requirements } = normalizeSourceRequirement(REQ_F_015);

    for (const requirement of requirements) {
      expect(requirement.sourceId).toBe("REQ-F-015");
      expect(requirement.id.startsWith("REQ-F-015")).toBe(true);
    }
  });

  it("emits canonical uppercase keywords and modal", () => {
    const { requirements } = normalizeSourceRequirement(REQ_F_015);

    for (const requirement of requirements) {
      expect(requirement.text).toContain("THE SYSTEM SHALL");
      expect(requirement.text).not.toMatch(/\bthe system shall\b/);
      expect(requirement.text).not.toMatch(/^When\b/);
    }
  });

  it("produces parts that each pass strict EARS validation", () => {
    const { requirements } = normalizeSourceRequirement(REQ_F_015);

    for (const requirement of requirements) {
      expect(validateEARSClause(requirement.text).valid).toBe(true);
    }
  });

  it("reports the split as a warning rather than performing it silently", () => {
    const { warnings } = normalizeSourceRequirement(REQ_F_015);

    expect(warnings.some((w) => /split into 2/.test(w.message))).toBe(true);
  });

  it("leaves a single-obligation requirement's ID unsuffixed", () => {
    const { requirements } = normalizeSourceRequirement(
      "REQ-F-002: [Event-driven] When the user presses Enter on the bill payment screen, the system shall process the payment entry."
    );

    expect(requirements).toHaveLength(1);
    expect(requirements[0].id).toBe("REQ-F-002");
    expect(requirements[0].split).toBe(false);
  });

  it("does not split a parenthesised field list", () => {
    // "(account ID, current balance, confirmation, and messages)" is one field
    // list belonging to a single obligation, not a series of obligations.
    const { requirements } = normalizeSourceRequirement(
      "REQ-F-003: [Event-driven] When the user presses PF4, the system shall clear all input fields (account ID, current balance, confirmation, and messages) and redisplay the bill payment screen."
    );

    expect(requirements).toHaveLength(2);
    expect(requirements[0].text).toContain(
      "(account ID, current balance, confirmation, and messages)"
    );
  });

  it("splits a three-part serial obligation list", () => {
    const { requirements } = normalizeSourceRequirement(
      "REQ-F-016: [Event-driven] When the write succeeds, the system shall clear all input fields, display a success message containing the transaction ID, and redisplay the bill payment screen."
    );

    expect(requirements.map((r) => r.id)).toEqual([
      "REQ-F-016a",
      "REQ-F-016b",
      "REQ-F-016c",
    ]);
  });

  it("does not split a noun list that contains no obligation verb", () => {
    const { requirements } = normalizeSourceRequirement(
      "REQ-F-001: [Ubiquitous] The system shall display the bill payment screen with the current date, current time, program name, and transaction identifier."
    );

    expect(requirements).toHaveLength(1);
  });

  it("corrects a pattern tag that disagrees with the text", () => {
    // Tagged event-driven, but the text has no trigger.
    const { requirements } = normalizeSourceRequirement(
      "REQ-F-099: [Event-driven] The system shall log all payment attempts."
    );

    expect(requirements[0].earsPattern).toBe("ubiquitous");
    expect(requirements[0].rendered).toContain("[Ubiquitous]");
  });

  it("omits the ID prefix when the source requirement has none", () => {
    const { requirements } = normalizeSourceRequirement(
      "WHEN a user submits a search query, THE SYSTEM SHALL return matching results."
    );

    expect(requirements[0].rendered).not.toMatch(/^\s*:/);
    expect(requirements[0].rendered).toMatch(/^\[Event-driven\] WHEN /);
  });

  it("accepts a trigger containing its own commas", () => {
    // The trigger boundary is the LAST comma before the actor. Anchoring on the
    // first would cut the trigger at "Enter," and report a well-formed
    // requirement as missing its comma.
    const { requirements, warnings } = normalizeSourceRequirement(
      "REQ-F-004: [Event-driven] When the user presses any key other than Enter, PF3, or PF4 on the bill payment screen, the system shall display an error message."
    );

    expect(warnings.filter((w) => /not strict EARS/.test(w.message))).toEqual([]);
    expect(validateEARSClause(requirements[0].text).valid).toBe(true);
  });

  it("accepts an IF trigger containing a parenthesised comma list", () => {
    const { requirements, warnings } = normalizeSourceRequirement(
      "REQ-SEC-002: [Unwanted] If the payment amount is not a valid numeric value (including NaN, Infinity, or non-numeric strings), the system shall reject the payment."
    );

    expect(warnings.filter((w) => /not strict EARS/.test(w.message))).toEqual([]);
    expect(requirements[0].text).toMatch(/^IF .*, THEN THE SYSTEM SHALL/);
  });

  it("splits a complex two-trigger requirement and keeps both triggers on each part", () => {
    const { requirements } = normalizeSourceRequirement(
      "REQ-F-012: [Complex] While the payment is confirmed and no error has occurred, when the system processes the payment, it shall retrieve the card cross-reference data for the account, determine the next transaction ID by reading the most recent transaction record."
    );

    expect(requirements.map((r) => r.id)).toEqual(["REQ-F-012a", "REQ-F-012b"]);
    expect(requirements[0].text).toContain("retrieve the card cross-reference data");
    expect(requirements[1].text).toContain("determine the next transaction ID");

    for (const requirement of requirements) {
      // Both stacked preconditions must survive the split, or the obligation
      // becomes unconditional.
      expect(requirement.text).toMatch(
        /^WHILE the payment is confirmed and no error has occurred, WHEN the system processes the payment, THE SYSTEM SHALL/
      );
      expect(validateEARSClause(requirement.text).valid).toBe(true);
    }
  });

  it("passes through an unrepairable requirement with a warning", () => {
    // A "requirement" with no SHALL cannot be made into one; dropping it would
    // silently remove content from the spec.
    const { requirements, warnings } = normalizeSourceRequirement(
      "REQ-F-050: [Ubiquitous] The payment screen is green."
    );

    expect(requirements).toHaveLength(1);
    expect(requirements[0].text).toContain("green");
    expect(warnings.some((w) => /not strict EARS/.test(w.message))).toBe(true);
  });
});
