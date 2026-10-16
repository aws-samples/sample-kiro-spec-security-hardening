import { describe, it, expect } from "vitest";
import { HardeningEngine } from "../src/engine/hardening-engine.js";
import { TriggerDetector } from "../src/engine/trigger-detector.js";
import { collectSemanticCandidates } from "../src/engine/semantic-candidates.js";
import { allMappings } from "../src/mappings/index.js";
import type { Requirement } from "../src/types/index.js";

/**
 * The motivating case: "any authenticated clinician can read any patient's notes"
 * is a CWE-862 object-level authorization gap, but it offers only one weak lexical
 * signal ("read") and so is scored below the default 0.3 threshold and dropped
 * from the deterministic output. The semantic-candidate band is what hands it to
 * the agent instead of losing it.
 */
const CLINICIAN_REQ: Requirement = {
  id: "R-CLINIC",
  text: "WHEN an authenticated clinician requests patient notes, THE SYSTEM SHALL read and return the notes.",
};

describe("collectSemanticCandidates", () => {
  it("surfaces CWE-862 for the clinician requirement the threshold would drop", () => {
    const detector = new TriggerDetector();
    const triggered = detector.detectTriggers(CLINICIAN_REQ);

    const cwe862 = triggered.find((t) => t.cweId === "CWE-862");
    expect(cwe862).toBeDefined();
    // Confirms the premise: it matched, but weakly enough to be filtered out.
    expect(cwe862!.confidence).toBeGreaterThan(0.05);
    expect(cwe862!.confidence).toBeLessThan(0.3);

    const candidates = collectSemanticCandidates(
      CLINICIAN_REQ,
      triggered,
      allMappings,
      new Set(), // nothing promoted above threshold
      { floor: 0.05, threshold: 0.3 }
    );

    const authz = candidates.find((c) => c.cweId === "CWE-862");
    expect(authz).toBeDefined();
    expect(authz!.candidateConstraints.length).toBeGreaterThan(0);
    // The adjudication question drives at the relationship predicate, not keywords.
    expect(authz!.reasoning.adjudicationQuestion.toLowerCase()).toContain(
      "relationship"
    );
  });

  it("defaults to the object-level authz scope, dropping incidental keyword noise", () => {
    const detector = new TriggerDetector();
    const triggered = detector.detectTriggers(CLINICIAN_REQ);

    // Default scope: authz only. CWE-79/319/400 etc. matched one keyword each but
    // are not object-level authorization concerns, so they must not appear.
    const candidates = collectSemanticCandidates(
      CLINICIAN_REQ,
      triggered,
      allMappings,
      new Set(),
      { floor: 0.05, threshold: 0.3 }
    );

    expect(candidates.some((c) => c.cweId === "CWE-862")).toBe(true);
    expect(candidates.every((c) => c.cweId === "CWE-862")).toBe(true);
  });

  it("surfaces the full band under the 'all' scope", () => {
    const detector = new TriggerDetector();
    const triggered = detector.detectTriggers(CLINICIAN_REQ);

    const all = collectSemanticCandidates(
      CLINICIAN_REQ,
      triggered,
      allMappings,
      new Set(),
      { scope: "all", floor: 0.05, threshold: 0.3 }
    );

    expect(all.length).toBeGreaterThan(1);
    expect(all.some((c) => c.cweId === "CWE-862")).toBe(true);
    // Object-level authz ranks first even in the broad sweep.
    expect(all[0].cweId).toBe("CWE-862");
  });

  it("returns no candidates for a benign requirement", () => {
    const detector = new TriggerDetector();
    const req: Requirement = {
      id: "R-TIME",
      text: "THE SYSTEM SHALL display the current server time in UTC.",
    };
    const triggered = detector.detectTriggers(req);

    const candidates = collectSemanticCandidates(
      req,
      triggered,
      allMappings,
      new Set(),
      { floor: 0.05, threshold: 0.3 }
    );

    expect(candidates).toHaveLength(0);
  });

  it("excludes CWEs already promoted above threshold", () => {
    const detector = new TriggerDetector();
    const triggered = detector.detectTriggers(CLINICIAN_REQ);

    const candidates = collectSemanticCandidates(
      CLINICIAN_REQ,
      triggered,
      allMappings,
      new Set(["CWE-862"]),
      { floor: 0.05, threshold: 0.3 }
    );

    expect(candidates.some((c) => c.cweId === "CWE-862")).toBe(false);
  });

  it("excludes scores at or below the floor", () => {
    const detector = new TriggerDetector();
    const triggered = detector.detectTriggers(CLINICIAN_REQ);

    // A floor above the CWE-862 score removes it from the band.
    const candidates = collectSemanticCandidates(
      CLINICIAN_REQ,
      triggered,
      allMappings,
      new Set(),
      { floor: 0.9, threshold: 1.0 }
    );

    expect(candidates.length).toBe(0);
  });
});

describe("HardeningEngine.getSemanticCandidates", () => {
  it("exposes candidates from the most recent harden run and resets between runs", () => {
    const engine = new HardeningEngine();

    engine.harden([CLINICIAN_REQ]);
    const candidates = engine.getSemanticCandidates();
    expect(candidates.some((c) => c.cweId === "CWE-862")).toBe(true);
    expect(candidates.every((c) => c.requirementId === "R-CLINIC")).toBe(true);

    // A clean second run must not leak the first run's candidates.
    engine.harden([{ id: "R-BENIGN", text: "THE SYSTEM SHALL display the current time in UTC." }]);
    expect(
      engine.getSemanticCandidates().some((c) => c.requirementId === "R-CLINIC")
    ).toBe(false);
  });

  it("keeps semantic candidates out of the applied proposals", () => {
    const engine = new HardeningEngine();
    const report = engine.harden([CLINICIAN_REQ]);

    // CWE-862 was surfaced as a candidate, so it must not also appear as an
    // applied proposal — the two paths are disjoint by confidence.
    const applied = report.results.flatMap((r) =>
      r.proposedRequirements.flatMap((p) => p.addressesCWEs)
    );
    const candidateCwes = engine.getSemanticCandidates().map((c) => c.cweId);
    for (const cwe of candidateCwes) {
      expect(applied).not.toContain(cwe);
    }
  });
});
