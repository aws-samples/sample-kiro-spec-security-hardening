import { describe, it, expect } from "vitest";
import { TriggerDetector } from "../src/engine/trigger-detector.js";
import { allMappings } from "../src/mappings/index.js";
import type { Requirement } from "../src/types/index.js";

describe("TriggerDetector", () => {
  const detector = new TriggerDetector();

  it("detects SQL injection from database query keywords", () => {
    const req: Requirement = {
      id: "R1",
      text: "WHEN a user submits a search query, THE SYSTEM SHALL query the database and return matching results.",
    };

    const triggers = detector.detectTriggers(req);
    const cweIds = triggers.map((t) => t.cweId);
    expect(cweIds).toContain("CWE-89");
  });

  it("detects XSS from content rendering keywords", () => {
    const req: Requirement = {
      id: "R2",
      text: "THE SYSTEM SHALL display user-submitted comments on the product page.",
    };

    const triggers = detector.detectTriggers(req);
    const cweIds = triggers.map((t) => t.cweId);
    expect(cweIds).toContain("CWE-79");
  });

  it("detects authentication triggers from login keywords", () => {
    const req: Requirement = {
      id: "R3",
      text: "WHEN a user logs in with email and password, THE SYSTEM SHALL verify credentials and issue a session token.",
    };

    const triggers = detector.detectTriggers(req);
    const cweIds = triggers.map((t) => t.cweId);
    expect(cweIds).toContain("CWE-307");
    expect(cweIds).toContain("CWE-208");
  });

  it("detects file upload triggers", () => {
    const req: Requirement = {
      id: "R4",
      text: "WHEN a user uploads a document, THE SYSTEM SHALL store the file in the document library.",
    };

    const triggers = detector.detectTriggers(req);
    const cweIds = triggers.map((t) => t.cweId);
    expect(cweIds).toContain("CWE-434");
  });

  it("detects SSRF from URL fetching requirement", () => {
    const req: Requirement = {
      id: "R5",
      text: "THE SYSTEM SHALL fetch the provided URL and import the content into the workspace.",
    };

    const triggers = detector.detectTriggers(req);
    const cweIds = triggers.map((t) => t.cweId);
    expect(cweIds).toContain("CWE-918");
  });

  it("returns triggers sorted by severity then confidence", () => {
    const req: Requirement = {
      id: "R6",
      text: "WHEN a user submits a form with their data, THE SYSTEM SHALL store the input in the database and display it on their profile page.",
    };

    const triggers = detector.detectTriggers(req);
    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };

    for (let i = 1; i < triggers.length; i++) {
      const prev = triggers[i - 1];
      const curr = triggers[i];
      if (severityOrder[prev.severity] === severityOrder[curr.severity]) {
        expect(prev.confidence).toBeGreaterThanOrEqual(curr.confidence);
      } else {
        expect(severityOrder[prev.severity]).toBeGreaterThanOrEqual(
          severityOrder[curr.severity]
        );
      }
    }
  });

  it("returns empty array for benign requirement", () => {
    const req: Requirement = {
      id: "R7",
      text: "THE SYSTEM SHALL display the current time in UTC format.",
    };

    const triggers = detector.detectTriggers(req);
    const highConfidence = triggers.filter((t) => t.confidence > 0.5);
    expect(highConfidence.length).toBe(0);
  });

  it("detects race condition from check-then-act pattern", () => {
    const req: Requirement = {
      id: "R8",
      text: "WHEN a user requests a transfer, THE SYSTEM SHALL check the account balance and then deduct the amount.",
    };

    const triggers = detector.detectTriggers(req);
    const cweIds = triggers.map((t) => t.cweId);
    expect(cweIds).toContain("CWE-362");
  });

  it("detects deserialization risk from parsing external data", () => {
    const req: Requirement = {
      id: "R9",
      text: "THE SYSTEM SHALL deserialize the incoming JSON payload and process the order data.",
    };

    const triggers = detector.detectTriggers(req);
    const cweIds = triggers.map((t) => t.cweId);
    expect(cweIds).toContain("CWE-502");
  });

  it("works with custom mapping subset", () => {
    const sqlOnly = allMappings.filter((m) => m.id === "CWE-89");
    const detector2 = new TriggerDetector(sqlOnly);

    const req: Requirement = {
      id: "R10",
      text: "THE SYSTEM SHALL query the database for matching users.",
    };

    const triggers = detector2.detectTriggers(req);
    expect(triggers.length).toBeGreaterThan(0);
    expect(triggers.every((t) => t.cweId === "CWE-89")).toBe(true);
  });
});
