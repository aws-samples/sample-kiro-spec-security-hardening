import { describe, it, expect } from "vitest";
import { detectSpecContext } from "../src/engine/spec-context.js";
import { HardeningEngine } from "../src/index.js";
import type { Requirement } from "../src/index.js";

const CHAT_SPEC = `# Requirements Document

Traffic is unencrypted TCP, accepted for a trusted LAN; TLS is out of scope. Profiles are kept in memory.

**Out of scope:** TLS or other encryption, direct messages between users.
`;

describe("detectSpecContext", () => {
  it("finds no database, HTTP or HTML in a TCP chat spec", () => {
    expect(detectSpecContext(CHAT_SPEC).features).toEqual([]);
  });

  it("collects out-of-scope statements at sentence level", () => {
    const { outOfScope } = detectSpecContext(CHAT_SPEC);
    expect(outOfScope).toContain("tls is out of scope.");
    expect(outOfScope.some((s) => s.includes("profiles are kept in memory"))).toBe(false);
  });

  it("collects every item under an Out of Scope heading", () => {
    const { outOfScope } = detectSpecContext("## Out of Scope\n\n- Encryption at rest\n\n## Next\n\n- kept\n");
    expect(outOfScope).toEqual(["- encryption at rest"]);
  });

  it("detects a database and web features where the spec names them", () => {
    const { features } = detectSpecContext("Users browse the web app; data lives in PostgreSQL tables via SQL.");
    expect(features).toEqual(expect.arrayContaining(["sql-database", "http"]));
  });
});

describe("context gating in the engine", () => {
  const search: Requirement[] = [
    { id: "R1", text: "WHEN a user submits a search query, THE SYSTEM SHALL return matching results from the database." },
  ];

  it("withholds SQL constraints when the spec shows no database, and says why", () => {
    const engine = new HardeningEngine();
    const report = engine.harden(search, { specContext: { features: [], outOfScope: [] } });
    const primitives = report.results[0].proposedRequirements.flatMap((p) => p.securityPrimitives);

    expect(primitives).not.toContain("parameterized-query");
    expect(engine.getSuppressedConstraints()).toContainEqual(
      expect.objectContaining({ cweId: "CWE-89", reason: expect.stringContaining("sql-database") })
    );
  });

  it("keeps SQL constraints when the spec has a database", () => {
    const report = new HardeningEngine().harden(search, {
      specContext: { features: ["sql-database"], outOfScope: [] },
    });
    const primitives = report.results[0].proposedRequirements.flatMap((p) => p.securityPrimitives);
    expect(primitives).toContain("parameterized-query");
  });

  it("withholds TLS when the spec declares TLS out of scope", () => {
    const req: Requirement[] = [
      { id: "R1", text: "WHEN the client transmits the password and personal data over the network, THE SYSTEM SHALL send it to the server." },
    ];
    const engine = new HardeningEngine();
    const report = engine.harden(req, { specContext: detectSpecContext(CHAT_SPEC) });
    const text = report.results.flatMap((r) => r.proposedRequirements.map((p) => p.text)).join(" ");

    expect(text).not.toMatch(/TLS/);
  });

  it("keeps password-storage rules off a requirement that only sends the password", () => {
    const req: Requirement[] = [
      { id: "R1", text: "WHEN the user registers, THE Chat_Client SHALL prompt for the password and send a registration request." },
      { id: "R2", text: "THE Chat_Server SHALL store the password of each user only as a password hash." },
    ];
    const report = new HardeningEngine().harden(req);
    const by = (id: string) =>
      report.results.find((r) => r.originalRequirement.id === id)!.proposedRequirements.flatMap((p) => p.securityPrimitives);

    expect(by("R1")).not.toContain("password-hashing");
    expect(by("R2")).toContain("password-hashing");
  });

  it("proposes Argon2id with OWASP minimum parameters, not bcrypt", () => {
    const req: Requirement[] = [
      { id: "R2", text: "THE SYSTEM SHALL store the password of each user only as a password hash." },
    ];
    const text = new HardeningEngine()
      .harden(req)
      .results[0].proposedRequirements.map((p) => p.text)
      .join(" ");
    expect(text).toContain("Argon2id using at least 19 MiB of memory, 2 iterations and a parallelism of 1");
    expect(text).not.toMatch(/bcrypt hashes/);
  });
});
