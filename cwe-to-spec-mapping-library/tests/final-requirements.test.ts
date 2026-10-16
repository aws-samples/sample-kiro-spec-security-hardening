import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm, readFile, writeFile, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  hardenMarkdownFile,
  parseRequirementsFromMarkdown,
} from "../src/cli/parse-and-harden.js";

const SOURCE = `# Requirements Document

## Requirements

### Requirement 1: Search

**User Story:** As a user, I want to search for other users by name.

#### Acceptance Criteria

1. WHEN a user submits a search query, THE SYSTEM SHALL return matching results from the database.
2. THE SYSTEM SHALL accept images up to 5MB in size.
`;

describe("in-place curated hardening", () => {
  let dir: string;
  let inputPath: string;
  let curatedContent: string;
  let unhardened: string[];

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "sis-curated-"));
    inputPath = join(dir, "requirements.md");
    await writeFile(inputPath, SOURCE, "utf-8");

    const result = await hardenMarkdownFile(inputPath);
    // Hardening edits the input file in place, so the deliverable is the input.
    expect(result!.outputPath).toBe(inputPath);
    curatedContent = await readFile(inputPath, "utf-8");

    unhardened = result!.report.results
      .filter((r) => r.proposedRequirements.length === 0)
      .map((r) => r.originalRequirement.text);
  });

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("writes no sidecar files", async () => {
    const exists = async (name: string) =>
      access(join(dir, name)).then(
        () => true,
        () => false
      );
    expect(await exists("final_requirements.md")).toBe(false);
    expect(await exists("requirements_hardened.md")).toBe(false);
  });

  it("preserves the surrounding document structure", () => {
    // Requirement lines are rewritten into strict EARS, so the document is no
    // longer byte-identical. Everything that is not a requirement or a security
    // constraint — headings, prose, blank lines — must survive untouched. This
    // source has only two requirements, so nothing is cross-cutting and no
    // baseline section is appended.
    const structural = (text: string) =>
      text
        .split("\n")
        .filter(
          (line) =>
            !line.includes("[SECURITY:") && !/\bSHALL\b|\bshall\b/.test(line)
        )
        .join("\n");

    expect(structural(curatedContent)).toBe(structural(SOURCE));
  });

  it("nests hardening statements under their parent requirement number", () => {
    expect(curatedContent).toMatch(
      /^ {3}1\.1\. SEC-\S+ \[SECURITY: [^\]]+\] .+/m
    );
  });

  it("rewrites requirements into canonical EARS keywords", () => {
    const requirementLines = curatedContent
      .split("\n")
      .filter((line) => /\bSHALL\b|\bshall\b/.test(line));

    expect(requirementLines.length).toBeGreaterThan(0);
    for (const line of requirementLines) {
      expect(line).not.toMatch(/\bthe system shall\b/);
      expect(line).not.toMatch(/\bshall\b/);
      expect(line).not.toMatch(/\b(?:When|If|While|Where)\b/);
    }
  });

  it("adds no per-constraint commentary", () => {
    expect(curatedContent).not.toContain("Rationale");
    expect(curatedContent).not.toContain("Addresses");
    expect(curatedContent).not.toContain("Triggered CWEs");
    expect(curatedContent).not.toContain("## Summary");
    expect(curatedContent).not.toContain("Generated from");
  });

  it("keeps every statement parsable as EARS", () => {
    const parsed = parseRequirementsFromMarkdown(curatedContent, inputPath);
    const securityStatements = parsed.filter((r) => r.securityAnnotations);

    expect(securityStatements.length).toBeGreaterThan(0);
    for (const statement of securityStatements) {
      expect(statement.text).toMatch(/\bSHALL\b/);
      expect(statement.text).not.toContain("[SECURITY:");
      expect(statement.earsPattern).toBeTruthy();
    }
  });

  it("leaves non-hardened requirements without sub-statements", () => {
    expect(unhardened.length).toBeGreaterThan(0);

    const lines = curatedContent.split("\n");
    for (const text of unhardened) {
      const index = lines.findIndex((l) => l.includes(text));
      expect(index).toBeGreaterThanOrEqual(0);
      expect(lines[index + 1] ?? "").not.toContain("[SECURITY:");
    }
  });

  it("recognises an ID-labelled requirement with no trigger and no explicit actor", () => {
    const source =
      "REQ-SEC-N-001: [Ubiquitous] All payment operations shall be logged to a tamper-evident audit trail.";

    const parsed = parseRequirementsFromMarkdown(source, "/tmp/requirements.md");

    expect(parsed).toHaveLength(1);
    expect(parsed[0].text).toContain("tamper-evident audit trail");
  });

  it("skips an already-hardened file and leaves it byte-identical", async () => {
    const before = await readFile(inputPath, "utf-8");
    const result = await hardenMarkdownFile(inputPath);
    const after = await readFile(inputPath, "utf-8");

    expect(result!.skipped).toBe(true);
    // Hardening output does not round-trip; re-running must be a true no-op
    // rather than re-normalize and corrupt the injected constraints.
    expect(after).toBe(before);
  });
});

describe("inline constraints adopt the spec's component subject", () => {
  // A spec written in the component's own voice rather than the canonical
  // `THE SYSTEM`. Inline hardening should match that voice for traceability.
  const COMPONENT_SOURCE = `# Requirements Document

## Requirements

### Requirement 1: Export

#### Acceptance Criteria

1. WHEN a user requests a data export by their user identifier, THE Cron_SDK SHALL generate a downloadable archive containing all user data.
`;

  let dir: string;
  let inputPath: string;
  let curated: string;

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "sis-component-"));
    inputPath = join(dir, "requirements.md");
    await writeFile(inputPath, COMPONENT_SOURCE, "utf-8");
    await hardenMarkdownFile(inputPath);
    curated = await readFile(inputPath, "utf-8");
  });

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("rewrites inline constraint subjects to the parent component", () => {
    const inlineConstraints = curated
      .split("\n")
      .filter((l) => /^\s+\d+\.\d+\./.test(l) && l.includes("[SECURITY:"));

    expect(inlineConstraints.length).toBeGreaterThan(0);
    for (const line of inlineConstraints) {
      expect(line).toContain("THE Cron_SDK SHALL");
      expect(line).not.toContain("THE SYSTEM");
    }
  });
});

describe("cross-cutting baseline consolidation", () => {
  // Three requirements that each independently trigger the same SQL-injection and
  // authentication constraints, so those clauses are cross-cutting.
  const MULTI = `# Requirements Document

## Requirements

### Requirement 1

#### Acceptance Criteria

1. WHEN a user submits a search query, THE SYSTEM SHALL return matching results from the database.

### Requirement 2

#### Acceptance Criteria

1. WHEN a user requests a data export by their user identifier, THE SYSTEM SHALL generate an archive from the database.

### Requirement 3

#### Acceptance Criteria

1. WHEN a user submits a login form with email, THE SYSTEM SHALL authenticate the user against the database.
`;

  let dir: string;
  let inputPath: string;
  let curated: string;
  let baselineCount: number;

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "sis-baseline-"));
    inputPath = join(dir, "requirements.md");
    await writeFile(inputPath, MULTI, "utf-8");
    const result = await hardenMarkdownFile(inputPath);
    baselineCount = result!.baselineConstraints;
    curated = await readFile(inputPath, "utf-8");
  });

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("lifts repeated clauses into a single baseline section", () => {
    expect(baselineCount).toBeGreaterThan(0);
    expect(curated).toContain("## Security Baseline (Cross-Cutting)");
    expect(curated).toMatch(/^- SEC-BASELINE-1 \[SECURITY: [^\]]+\] .+/m);
  });

  it("states each cross-cutting clause exactly once", () => {
    // A parameterized-query clause is proposed for all three requirements; after
    // consolidation it must appear a single time in the whole document.
    const paramQueryLines = curated
      .split("\n")
      .filter((l) =>
        l.includes(
          "parameterized statements or prepared statements only"
        )
      );
    expect(paramQueryLines).toHaveLength(1);
    expect(paramQueryLines[0]).toContain("SEC-BASELINE-");
  });

  it("does not repeat a baseline clause inline under any requirement", () => {
    const inlineParamQuery = curated
      .split("\n")
      .filter(
        (l) =>
          /^\s+\d+\.\d+\./.test(l) &&
          l.includes("parameterized statements or prepared statements only")
      );
    expect(inlineParamQuery).toHaveLength(0);
  });
});
