import { describe, it, expect } from "vitest";
import { fillTemplate, resolveTemplate } from "../src/engine/template-filler.js";
import { detectSpecContext } from "../src/engine/spec-context.js";
import { getMappingById } from "../src/mappings/index.js";
import { HardeningEngine } from "../src/index.js";
import type { EARSConstraint } from "../src/types/index.js";

const constraint = (cwe: string, id: string): EARSConstraint =>
  getMappingById(cwe)!.earsConstraints.find((c) => c.id === id)!;

describe("resolveTemplate", () => {
  it("uses neutral wording unless the spec has the variant's feature", () => {
    const upload = constraint("CWE-434", "EC-434-2");
    expect(resolveTemplate(upload, { features: [], outOfScope: [] })).not.toContain("document root");
    expect(resolveTemplate(upload, { features: ["http"], outOfScope: [] })).toContain("web-accessible document root");
  });

  it("mentions database schema details only for a spec with a database", () => {
    const errors = constraint("CWE-209", "EC-209-1");
    expect(resolveTemplate(errors, { features: [], outOfScope: [] })).not.toContain("database");
    expect(resolveTemplate(errors, { features: ["sql-database"], outOfScope: [] })).toContain("database schema details");
  });

  it("cites the spec's own language in examples", () => {
    const deser = constraint("CWE-502", "EC-502-1");
    const go = resolveTemplate(deser, { features: [], outOfScope: [], languages: ["go"] });
    expect(go).toContain("Go encoding/gob");
    expect(go).not.toMatch(/Java|Python/);
  });

  it("falls back to cross-language examples when no language is named", () => {
    const text = resolveTemplate(constraint("CWE-502", "EC-502-1"), { features: [], outOfScope: [] });
    expect(text).toContain("Java ObjectInputStream");
    expect(text).not.toContain("{");
  });
});

describe("detectSpecContext languages", () => {
  it("recognizes Go from specific phrasing, not the English verb", () => {
    expect(detectSpecContext("The server is written in Go and needs Go 1.22.").languages).toEqual(["go"]);
    expect(detectSpecContext("Users go to the settings page and go back.").languages).toEqual([]);
  });

  it("recognizes other languages", () => {
    expect(detectSpecContext("A Django service in Python.").languages).toContain("python");
    expect(detectSpecContext("Runs on Node.js with TypeScript.").languages).toContain("javascript");
    expect(detectSpecContext("An ASP.NET Core app in C#.").languages).toContain("dotnet");
  });
});

describe("fillTemplate", () => {
  it("reports placeholders that fell back to generic text", () => {
    const { text, genericSlots } = fillTemplate(
      "WHEN {actor} requests a privilege escalation for {target}, THE SYSTEM SHALL verify the actor holds the {required_role} role."
    );
    expect(text).toContain("holds the required role");
    expect(genericSlots.map((g) => g.slot)).toEqual(["target", "required_role"]);
  });

  it("does not report the actor fallback, which reads as complete", () => {
    expect(fillTemplate("WHEN {actor} uploads a file, THE SYSTEM SHALL scan it.").genericSlots).toEqual([]);
  });

  it("fills {operation} with the requirement's verb phrase", () => {
    const { text, genericSlots } = fillTemplate(
      "WHEN {actor} requests to {operation}, THE SYSTEM SHALL verify the actor holds the role.",
      "WHEN a user creates a room, THE Room_Manager SHALL assign the room creator as moderator."
    );
    expect(text).toContain("WHEN a user requests to assign the room,");
    expect(genericSlots).toEqual([]);
  });
});

describe("engine output for generic and candidate templates", () => {
  it("marks proposals built from generic fallbacks", () => {
    const report = new HardeningEngine().harden([
      { id: "R1", text: "WHEN a room is created, THE Room_Manager SHALL grant the moderator role and permission to the creator." },
    ]);
    const escalation = report.results[0].proposedRequirements.filter((p) => p.addressesCWEs.includes("CWE-269"));
    expect(escalation.length).toBeGreaterThan(0);
    expect(escalation.every((p) => p.genericSlots?.some((g) => g.slot === "target"))).toBe(true);
  });

  it("shows semantic-review candidates filled, in the requirement's subject", () => {
    const engine = new HardeningEngine();
    engine.harden([
      { id: "R1", text: "WHEN an authenticated clinician requests patient notes, THE Notes_Service SHALL read and return the notes." },
    ]);
    const templates = engine.getSemanticCandidates().flatMap((c) => c.candidateConstraints.map((k) => k.template));
    expect(templates.length).toBeGreaterThan(0);
    for (const template of templates) {
      expect(template).not.toMatch(/\{\w+\}/);
      expect(template).not.toContain("THE SYSTEM");
    }
  });
});
