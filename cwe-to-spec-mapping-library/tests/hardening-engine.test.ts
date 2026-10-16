import { describe, it, expect } from "vitest";
import { HardeningEngine, formatAsSecurityAnnotatedEARS } from "../src/index.js";
import type { Requirement } from "../src/index.js";

describe("HardeningEngine", () => {
  const engine = new HardeningEngine();

  describe("SQL Injection scenario (CWE-89)", () => {
    const requirements: Requirement[] = [
      {
        id: "REQ-1",
        text: "WHEN a physician searches for clinical notes by patient name, THE SYSTEM SHALL return all matching clinical notes from the records database.",
        earsPattern: "event-driven",
      },
    ];

    it("detects SQL injection triggers from database query requirement", () => {
      const report = engine.harden(requirements);
      const result = report.results[0];

      const cweIds = result.triggeredCWEs.map((t) => t.cweId);
      expect(cweIds).toContain("CWE-89");
    });

    it("proposes parameterized query constraint", () => {
      const report = engine.harden(requirements);
      const result = report.results[0];

      const primitives = result.proposedRequirements.flatMap(
        (p) => p.securityPrimitives
      );
      expect(primitives).toContain("parameterized-query");
    });

    it("marks SQL injection proposals as mandatory priority", () => {
      const report = engine.harden(requirements);
      const result = report.results[0];

      const sqlProposals = result.proposedRequirements.filter((p) =>
        p.addressesCWEs.includes("CWE-89")
      );
      expect(sqlProposals.every((p) => p.priority === "mandatory")).toBe(true);
    });
  });

  describe("Authentication scenario (CWE-306)", () => {
    const requirements: Requirement[] = [
      {
        id: "REQ-2",
        text: "THE SYSTEM SHALL expose an API endpoint that returns user account details.",
        earsPattern: "ubiquitous",
      },
    ];

    it("detects missing authentication trigger", () => {
      const report = engine.harden(requirements);
      const result = report.results[0];

      const cweIds = result.triggeredCWEs.map((t) => t.cweId);
      expect(cweIds).toContain("CWE-306");
    });

    it("proposes authentication-required constraint", () => {
      const report = engine.harden(requirements);
      const result = report.results[0];

      const primitives = result.proposedRequirements.flatMap(
        (p) => p.securityPrimitives
      );
      expect(primitives).toContain("authentication-required");
    });
  });

  describe("File upload scenario (CWE-434)", () => {
    const requirements: Requirement[] = [
      {
        id: "REQ-3",
        text: "WHEN a user uploads a profile image, THE SYSTEM SHALL store the file and display it on the user profile page.",
        earsPattern: "event-driven",
      },
    ];

    it("detects file upload triggers", () => {
      const report = engine.harden(requirements);
      const result = report.results[0];

      const cweIds = result.triggeredCWEs.map((t) => t.cweId);
      expect(cweIds).toContain("CWE-434");
    });

    it("proposes file type validation", () => {
      const report = engine.harden(requirements);
      const result = report.results[0];

      const primitives = result.proposedRequirements.flatMap(
        (p) => p.securityPrimitives
      );
      expect(primitives).toContain("file-type-validation");
    });

    it("also detects authentication risk from exposed endpoint", () => {
      const report = engine.harden(requirements);
      const result = report.results[0];

      const cweIds = result.triggeredCWEs.map((t) => t.cweId);
      expect(cweIds).toContain("CWE-306");
    });
  });

  describe("Webhook delivery scenario (CWE-201, CWE-918)", () => {
    const requirements: Requirement[] = [
      {
        id: "REQ-4",
        text: "WHEN an integration event is triggered, THE SYSTEM SHALL deliver the full event payload to the customer-configured webhook endpoint via HTTP POST.",
        earsPattern: "event-driven",
      },
    ];

    it("detects data exposure risk in outbound payload", () => {
      const report = engine.harden(requirements);
      const result = report.results[0];

      const cweIds = result.triggeredCWEs.map((t) => t.cweId);
      expect(cweIds).toContain("CWE-201");
    });

    it("proposes outbound data allowlist", () => {
      const report = engine.harden(requirements);
      const result = report.results[0];

      const primitives = result.proposedRequirements.flatMap(
        (p) => p.securityPrimitives
      );
      expect(primitives).toContain("outbound-data-allowlist");
    });
  });

  describe("Multi-requirement coverage", () => {
    const requirements: Requirement[] = [
      {
        id: "REQ-5",
        text: "WHEN a user submits a login form with email and password, THE SYSTEM SHALL authenticate the user and create a session.",
        earsPattern: "event-driven",
      },
      {
        id: "REQ-6",
        text: "THE SYSTEM SHALL store user passwords securely.",
        earsPattern: "ubiquitous",
      },
    ];

    it("detects brute force and credential storage risks", () => {
      const report = engine.harden(requirements);

      const allCWEs = report.results.flatMap((r) =>
        r.triggeredCWEs.map((t) => t.cweId)
      );
      expect(allCWEs).toContain("CWE-307");
      expect(allCWEs).toContain("CWE-522");
    });

    it("produces a summary with gap counts", () => {
      const report = engine.harden(requirements);

      expect(report.summary.totalRequirements).toBe(2);
      expect(report.summary.totalCWEsTriggered).toBeGreaterThan(0);
      expect(report.summary.totalProposedAdditions).toBeGreaterThan(0);
    });
  });

  describe("Already-covered requirement", () => {
    const requirements: Requirement[] = [
      {
        id: "REQ-7",
        text: "WHEN a user submits a search query, THE SYSTEM SHALL execute all database queries using parameterized statements only. THE SYSTEM SHALL sanitize all input parameters against an allowlisted character set.",
        earsPattern: "event-driven",
        securityAnnotations: ["parameterized-query", "input-validation"],
      },
    ];

    it("has higher coverage score for already-hardened requirements", () => {
      const report = engine.harden(requirements);
      const result = report.results[0];

      expect(result.coverageScore).toBeGreaterThan(0.5);
    });
  });

  describe("Report formatting", () => {
    it("produces valid formatted output", () => {
      const requirements: Requirement[] = [
        {
          id: "REQ-8",
          text: "WHEN a user requests a report export by report identifier, THE SYSTEM SHALL generate and return a downloadable CSV file.",
          earsPattern: "event-driven",
        },
      ];

      const report = engine.harden(requirements);
      const formatted = formatAsSecurityAnnotatedEARS(report);

      expect(formatted).toContain("# Original: REQ-8");
      expect(formatted).toContain("[SECURITY:");
      expect(formatted).toContain("Addresses:");
      expect(formatted).toContain("Priority:");
      expect(formatted).toContain("## Summary");
    });
  });

  describe("Confidence threshold filtering", () => {
    const requirements: Requirement[] = [
      {
        id: "REQ-9",
        text: "THE SYSTEM SHALL display a welcome message on the homepage.",
        earsPattern: "ubiquitous",
      },
    ];

    it("filters out low-confidence triggers with high threshold", () => {
      const report = engine.harden(requirements, {
        confidenceThreshold: 0.8,
      });
      const result = report.results[0];

      expect(result.triggeredCWEs.length).toBeLessThanOrEqual(
        engine.harden(requirements, { confidenceThreshold: 0.1 }).results[0]
          .triggeredCWEs.length
      );
    });
  });

  describe("SSRF scenario (CWE-918)", () => {
    const requirements: Requirement[] = [
      {
        id: "REQ-10",
        text: "WHEN a user submits a URL to import, THE SYSTEM SHALL fetch the content from the user-specified endpoint and import it into the workspace.",
        earsPattern: "event-driven",
      },
    ];

    it("detects SSRF risk", () => {
      const report = engine.harden(requirements);
      const result = report.results[0];

      const cweIds = result.triggeredCWEs.map((t) => t.cweId);
      expect(cweIds).toContain("CWE-918");
    });

    it("proposes SSRF prevention constraint", () => {
      const report = engine.harden(requirements);
      const result = report.results[0];

      const primitives = result.proposedRequirements.flatMap(
        (p) => p.securityPrimitives
      );
      expect(primitives).toContain("ssrf-prevention");
    });
  });

  describe("Authorization bypass scenario (CWE-639)", () => {
    const requirements: Requirement[] = [
      {
        id: "REQ-11",
        text: "WHEN an authenticated user requests a report export by report identifier, THE SYSTEM SHALL generate and return the report data.",
        earsPattern: "event-driven",
      },
    ];

    it("detects IDOR risk from user-controlled identifier", () => {
      const report = engine.harden(requirements);
      const result = report.results[0];

      const cweIds = result.triggeredCWEs.map((t) => t.cweId);
      expect(cweIds).toContain("CWE-639");
    });

    it("proposes IDOR prevention", () => {
      const report = engine.harden(requirements);
      const result = report.results[0];

      const primitives = result.proposedRequirements.flatMap(
        (p) => p.securityPrimitives
      );
      expect(primitives).toContain("idor-prevention");
    });
  });
});
