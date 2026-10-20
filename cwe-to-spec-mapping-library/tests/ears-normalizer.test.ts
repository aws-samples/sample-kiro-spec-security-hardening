import { describe, it, expect } from "vitest";
import {
  atomizeTemplate,
  hoistEmbeddedPrecondition,
  isHoistableEvent,
  classifyEARSPattern,
  isValidActorPhrase,
  normalizeEARSClause,
  toValidEARSClauses,
  validateEARSClause,
} from "../src/index.js";

describe("isValidActorPhrase", () => {
  it("accepts bare agent noun phrases", () => {
    expect(isValidActorPhrase("user")).toBe(true);
    expect(isValidActorPhrase("administrator")).toBe(true);
    expect(isValidActorPhrase("authenticated user")).toBe(true);
  });

  it("rejects verb-terminated captures (the doubled-verb defect)", () => {
    expect(isValidActorPhrase("user submits")).toBe(false);
    expect(isValidActorPhrase("system processes")).toBe(false);
    expect(isValidActorPhrase("account is")).toBe(false);
  });

  it("rejects non-agent nouns that cannot perform an action", () => {
    expect(isValidActorPhrase("duplicate key")).toBe(false);
    expect(isValidActorPhrase("write error")).toBe(false);
    expect(isValidActorPhrase("browse start")).toBe(false);
    expect(isValidActorPhrase("end of")).toBe(false);
  });

  it("rejects over-long phrases", () => {
    expect(isValidActorPhrase("user with an active session context")).toBe(false);
  });
});

describe("atomizeTemplate", () => {
  it("splits a compound template into atomic clauses", () => {
    const clauses = atomizeTemplate(
      "THE SYSTEM SHALL execute all database queries using parameterized statements or prepared statements only. THE SYSTEM SHALL NOT construct query strings by concatenation of user-supplied values."
    );
    expect(clauses).toHaveLength(2);
    expect(clauses[0]).toMatch(/^THE SYSTEM SHALL execute/);
    expect(clauses[1]).toMatch(/^THE SYSTEM SHALL NOT construct/);
  });

  it("does not split on sentence-internal periods", () => {
    const clauses = atomizeTemplate(
      "THE SYSTEM SHALL transmit all sensitive data exclusively over TLS 1.2 or higher."
    );
    expect(clauses).toHaveLength(1);
    expect(clauses[0]).toContain("TLS 1.2");
  });

  it("keeps IP-range and pickle literals intact", () => {
    const clauses = atomizeTemplate(
      "WHEN the system fetches a user-supplied URL, THE SYSTEM SHALL reject any URL whose host resolves to a link-local range (169.254.0.0/16) or loopback address."
    );
    expect(clauses).toHaveLength(1);
    expect(clauses[0]).toContain("169.254.0.0/16");
  });

  it("propagates the trigger to follow-on clauses", () => {
    const clauses = atomizeTemplate(
      "WHEN the system generates output, THE SYSTEM SHALL do the first thing. THE SYSTEM SHALL do the second thing."
    );
    expect(clauses).toHaveLength(2);
    expect(clauses[1]).toMatch(/^WHEN the system generates output,/);
  });
});

describe("normalizeEARSClause", () => {
  it("resolves 'it SHALL' to 'THE SYSTEM SHALL' when the trigger's subject is the system", () => {
    const result = normalizeEARSClause(
      "When the system creates the payment transaction record, it shall populate the record with transaction type '02'."
    );

    expect(result).toContain("THE SYSTEM SHALL populate");
    expect(result).not.toMatch(/\bit SHALL\b/);
  });

  it("resolves the pronoun using the nearest trigger's subject, not its last noun", () => {
    // The nearest trigger's last noun is "the payment", but its subject is the
    // system — a nearest-noun rule would wrongly refuse this clause.
    const result = normalizeEARSClause(
      "While the payment is confirmed, when the system processes the payment, it shall retrieve the card cross-reference data."
    );

    expect(result).toContain("THE SYSTEM SHALL retrieve");
  });

  it("leaves 'it SHALL' alone when the trigger's subject is not the system", () => {
    // "it" plausibly refers to the batch job. Substituting would silently
    // reassign the requirement's subject, so this stays for a human to resolve.
    const clause =
      "WHEN the batch job completes, it SHALL write a summary record.";

    expect(normalizeEARSClause(clause)).toBe(clause);
    expect(validateEARSClause(normalizeEARSClause(clause)).valid).toBe(false);
  });

  it("uppercases the second keyword of a complex two-trigger clause", () => {
    const result = normalizeEARSClause(
      "While the payment is confirmed, when the system processes the payment, it shall retrieve the card data."
    );

    expect(result).toMatch(/^WHILE .*, WHEN the system processes the payment,/);
  });

  it("does not uppercase trigger words used as prose in the response body", () => {
    // "when available" is an aside inside the response, not an EARS trigger.
    const result = normalizeEARSClause(
      "WHEN a payment settles, THE SYSTEM SHALL log the settlement time, when available, to the audit trail."
    );

    expect(result).toContain(", when available,");
  });

  it("inserts THEN into an IF clause that lacks it", () => {
    const result = normalizeEARSClause(
      "IF no valid credential is present, THE SYSTEM SHALL return HTTP 401."
    );
    expect(result).toBe(
      "IF no valid credential is present, THEN THE SYSTEM SHALL return HTTP 401."
    );
  });

  it("leaves a well-formed IF clause unchanged", () => {
    const clause =
      "IF the principal does not own the resource, THEN THE SYSTEM SHALL return HTTP 403.";
    expect(normalizeEARSClause(clause)).toBe(clause);
  });

  it("uppercases the actor", () => {
    expect(normalizeEARSClause("the system shall log the event.")).toBe(
      "THE SYSTEM SHALL log the event."
    );
  });
});

describe("classifyEARSPattern", () => {
  it("classifies IF as unwanted-behavior, not state-driven", () => {
    expect(
      classifyEARSPattern("IF x, THEN THE SYSTEM SHALL reject.")
    ).toBe("unwanted-behavior");
  });

  it("classifies WHEN as event-driven", () => {
    expect(
      classifyEARSPattern("WHEN a user submits input, THE SYSTEM SHALL validate it.")
    ).toBe("event-driven");
  });

  it("classifies a plain SHALL as ubiquitous", () => {
    expect(classifyEARSPattern("THE SYSTEM SHALL encrypt all data.")).toBe(
      "ubiquitous"
    );
  });

  it("classifies stacked WHILE+WHEN as complex", () => {
    expect(
      classifyEARSPattern(
        "WHILE the account is valid, WHEN the user confirms, THE SYSTEM SHALL process."
      )
    ).toBe("complex");
  });

  it("does not treat SHALL NOT as a pattern selector", () => {
    expect(
      classifyEARSPattern("THE SYSTEM SHALL NOT store plaintext passwords.")
    ).toBe("ubiquitous");
  });
});

describe("validateEARSClause", () => {
  it("passes a well-formed ubiquitous clause", () => {
    expect(
      validateEARSClause("THE SYSTEM SHALL encrypt all data at rest.").valid
    ).toBe(true);
  });

  it("flags an unsubstituted placeholder", () => {
    const r = validateEARSClause("WHEN {actor} submits input, THE SYSTEM SHALL validate.");
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/placeholder/);
  });

  it("flags a compound clause", () => {
    const r = validateEARSClause(
      "THE SYSTEM SHALL do one thing. THE SYSTEM SHALL do another."
    );
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/compound/);
  });

  it("flags an IF clause missing THEN", () => {
    const r = validateEARSClause(
      "IF the token is absent, THE SYSTEM SHALL reject the request."
    );
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/THEN/);
  });

  it("flags the doubled-verb trigger", () => {
    const r = validateEARSClause(
      "WHEN user submits submits the input, THE SYSTEM SHALL sanitize it."
    );
    expect(r.valid).toBe(false);
    expect(r.errors.join(" ")).toMatch(/malformed trigger/);
  });

  it("flags a passive assertion with no actor", () => {
    const r = validateEARSClause("Sensitive fields SHALL be replaced with a placeholder.");
    expect(r.valid).toBe(false);
  });
});

describe("toValidEARSClauses (full pipeline)", () => {
  it("splits an AND-conjoined IF template and propagates the precondition", () => {
    const { clauses, rejected } = toValidEARSClauses(
      "IF no valid authentication credential is present in the request, THE SYSTEM SHALL return HTTP 401 with no data payload AND SHALL NOT process the request further."
    );
    expect(rejected).toHaveLength(0);

    // `AND SHALL NOT` joins two independently testable obligations, so EARS
    // atomicity requires two requirements rather than one.
    expect(clauses).toHaveLength(2);
    clauses.forEach((c) => expect(c).toMatch(/^IF .*, THEN THE SYSTEM SHALL/));

    // The continuation must keep the precondition; without it the prohibition
    // would read as unconditional.
    expect(clauses[1]).toContain("no valid authentication credential");
  });

  it("produces two valid clauses from the parameterized-query template", () => {
    const { clauses, rejected } = toValidEARSClauses(
      "THE SYSTEM SHALL execute all database queries using parameterized statements or prepared statements only. THE SYSTEM SHALL NOT construct query strings by concatenation of user-supplied values."
    );
    expect(rejected).toHaveLength(0);
    expect(clauses).toHaveLength(2);
    clauses.forEach((c) => expect(validateEARSClause(c).valid).toBe(true));
  });
});

describe("named component actors", () => {
  it("accepts THE <Component> SHALL as an explicit actor", () => {
    expect(validateEARSClause("THE Chat_Server SHALL keep a Muted_Room muted until a Moderator unmutes the Room.").valid).toBe(true);
    expect(validateEARSClause("THE Payment Service SHALL reject the refund.").valid).toBe(true);
  });

  it("still rejects a passive clause with no actor", () => {
    const result = validateEARSClause("Sensitive fields SHALL be replaced.");
    expect(result.valid).toBe(false);
  });

  it("accepts and classifies a WHERE + IF complex requirement", () => {
    const clause =
      "WHERE a Data_Directory is configured, IF a line of a history file cannot be decoded, THEN THE Chat_Server SHALL skip that line.";
    const result = validateEARSClause(clause);
    expect(result.errors).toEqual([]);
    expect(classifyEARSPattern(clause)).toBe("complex");
  });

  it("accepts a WHERE + WHEN complex requirement naming a component", () => {
    const clause =
      "WHERE the Message_Search extension is provided, WHEN the user enters /search <text>, THE Chat_Client SHALL send a search request.";
    expect(validateEARSClause(clause).errors).toEqual([]);
  });
});

describe("moving a 'before ...' qualifier", () => {
  it("leaves a bare-noun qualifier in the response", () => {
    expect(hoistEmbeddedPrecondition("THE SYSTEM SHALL validate the data before use.")).toBe(
      "THE SYSTEM SHALL validate the data before use."
    );
    expect(hoistEmbeddedPrecondition("THE SYSTEM SHALL lock the account before the deadline.")).toBe(
      "THE SYSTEM SHALL lock the account before the deadline."
    );
  });

  it("still moves a gerund phrase or a clause with its own verb", () => {
    expect(hoistEmbeddedPrecondition("THE SYSTEM SHALL verify ownership before executing the operation.")).toBe(
      "WHILE the operation is being executed, THE SYSTEM SHALL verify ownership."
    );
    expect(isHoistableEvent("the token expires")).toBe(true);
    expect(isHoistableEvent("use")).toBe(false);
    expect(isHoistableEvent("deployment")).toBe(false);
  });

  it("accepts a generated clause that keeps a bare-noun qualifier", () => {
    expect(validateEARSClause("THE SYSTEM SHALL validate the data before use.").valid).toBe(true);
  });

  it("rejects a one-word trigger", () => {
    const result = validateEARSClause("WHEN use, THE SYSTEM SHALL validate the data.");
    expect(result.errors.join(" ")).toMatch(/names no event or state/);
  });
});
