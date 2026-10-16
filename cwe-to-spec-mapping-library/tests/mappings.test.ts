import { describe, it, expect } from "vitest";
import {
  allMappings,
  getMappingById,
  getMappingsByTag,
  getMappingsByOwasp,
  getMappingsBySeverity,
} from "../src/mappings/index.js";
import { toValidEARSClauses } from "../src/engine/ears-normalizer.js";

describe("Mappings registry", () => {
  it("has at least 40 CWE mappings", () => {
    expect(allMappings.length).toBeGreaterThanOrEqual(40);
  });

  it("all mappings have valid structure", () => {
    for (const mapping of allMappings) {
      expect(mapping.id).toMatch(/^CWE-\d+$/);
      expect(mapping.name).toBeTruthy();
      expect(mapping.description).toBeTruthy();
      expect(mapping.triggerConditions.length).toBeGreaterThan(0);
      expect(mapping.earsConstraints.length).toBeGreaterThan(0);
      expect(["critical", "high", "medium", "low"]).toContain(mapping.severity);
      expect(mapping.tags.length).toBeGreaterThan(0);
    }
  });

  it("all trigger conditions have keywords and patterns", () => {
    for (const mapping of allMappings) {
      for (const trigger of mapping.triggerConditions) {
        expect(trigger.id).toBeTruthy();
        expect(trigger.keywords.length).toBeGreaterThan(0);
        expect(trigger.semanticPatterns.length).toBeGreaterThan(0);
      }
    }
  });

  it("all EARS constraints have valid patterns", () => {
    const validPatterns = [
      "ubiquitous",
      "event-driven",
      "state-driven",
      "optional-feature",
      "unwanted-behavior",
      "complex",
    ];

    for (const mapping of allMappings) {
      for (const constraint of mapping.earsConstraints) {
        expect(validPatterns).toContain(constraint.pattern);
        expect(constraint.template).toBeTruthy();
        expect(constraint.securityPrimitive).toBeTruthy();
        expect(constraint.rationale).toBeTruthy();
      }
    }
  });

  it("every constraint template yields only strict-EARS clauses", () => {
    // The pipeline gate is what keeps invalid text out of a delivered spec, so a
    // template that cannot pass it is a defect in the template itself. Asserting
    // this over the whole registry catches a regression at the source rather
    // than as unparseable output in someone's requirements document.
    const fill = (template: string) =>
      template
        .replace(/\{actor\}/g, "a user")
        .replace(/\{operation\}/g, "the operation")
        .replace(/\{resource\}/g, "the resource")
        .replace(/\{input_description\}/g, "the input")
        .replace(/\{target_state\}/g, "the target state")
        .replace(/\{target\}/g, "the target")
        .replace(/\{required_role\}/g, "the required")
        .replace(/\{high_value_operation\}/g, "the operation")
        .replace(/\{configured_limit\}/g, "the configured limit");

    const failures: string[] = [];

    for (const mapping of allMappings) {
      for (const constraint of mapping.earsConstraints) {
        const { clauses, rejected } = toValidEARSClauses(fill(constraint.template));

        if (rejected.length > 0) {
          failures.push(
            `${mapping.id}/${constraint.id}: ${rejected
              .map((r) => r.errors.join(", "))
              .join(" | ")}`
          );
        }

        // A template must yield at least one clause; emitting none would drop a
        // security constraint silently.
        expect(clauses.length).toBeGreaterThan(0);
      }
    }

    expect(failures).toEqual([]);
  });

  it("covers all OWASP Top 10 2021 categories", () => {
    const owaspCategories = allMappings
      .map((m) => m.owaspCategory)
      .filter(Boolean);
    const unique = [...new Set(owaspCategories)];

    expect(unique).toContain("A01:2021-Broken Access Control");
    expect(unique).toContain("A02:2021-Cryptographic Failures");
    expect(unique).toContain("A03:2021-Injection");
    expect(unique).toContain("A04:2021-Insecure Design");
    expect(unique).toContain("A05:2021-Security Misconfiguration");
    expect(unique).toContain("A06:2021-Vulnerable and Outdated Components");
    expect(unique).toContain("A07:2021-Identification and Authentication Failures");
    expect(unique).toContain("A08:2021-Software and Data Integrity Failures");
    expect(unique).toContain("A09:2021-Security Logging and Monitoring Failures");
    expect(unique).toContain("A10:2021-Server-Side Request Forgery");
  });

  describe("getMappingById", () => {
    it("returns mapping for known CWE", () => {
      const mapping = getMappingById("CWE-89");
      expect(mapping).toBeDefined();
      expect(mapping!.name).toBe("SQL Injection");
    });

    it("returns undefined for unknown CWE", () => {
      expect(getMappingById("CWE-99999")).toBeUndefined();
    });
  });

  describe("getMappingsByTag", () => {
    it("returns injection mappings", () => {
      const results = getMappingsByTag("injection");
      expect(results.length).toBeGreaterThan(0);
      expect(results.every((m) => m.tags.includes("injection"))).toBe(true);
    });
  });

  describe("getMappingsByOwasp", () => {
    it("returns Broken Access Control mappings", () => {
      const results = getMappingsByOwasp("A01:2021-Broken Access Control");
      expect(results.length).toBeGreaterThan(0);
    });
  });

  describe("getMappingsBySeverity", () => {
    it("returns critical mappings", () => {
      const results = getMappingsBySeverity("critical");
      expect(results.length).toBeGreaterThan(0);
      expect(results.every((m) => m.severity === "critical")).toBe(true);
    });
  });
});
