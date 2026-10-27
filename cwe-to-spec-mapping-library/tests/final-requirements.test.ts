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
    dir = await mkdtemp(join(tmpdir(), "spec-hardening-curated-"));
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

  it("keeps every original line, unchanged and in order", () => {
    // Hardening only inserts lines. Removing the inserted constraint lines and
    // the review marker must give back the source byte for byte.
    const withoutAdditions = curatedContent
      .replace(/\n<!-- spec-it-safe:reviewed[\s\S]*?-->\n/, "")
      .split("\n")
      .filter((line) => !line.includes("[SECURITY:"))
      .join("\n");

    expect(withoutAdditions).toBe(SOURCE);
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

  it("treats a re-run with no new requirements as up to date and leaves it byte-identical", async () => {
    const before = await readFile(inputPath, "utf-8");
    const result = await hardenMarkdownFile(inputPath);
    const after = await readFile(inputPath, "utf-8");

    expect(result!.skipped).toBe(true);
    expect(result!.mode).toBe("up-to-date");
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
    dir = await mkdtemp(join(tmpdir(), "spec-hardening-component-"));
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

1. WHEN an analyst submits a filter query, THE SYSTEM SHALL fetch matching records from the database.

### Requirement 3

#### Acceptance Criteria

1. WHEN an administrator submits a report query, THE SYSTEM SHALL query records from the database.
`;

  let dir: string;
  let inputPath: string;
  let curated: string;
  let baselineCount: number;

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "spec-hardening-baseline-"));
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

describe("hardening never changes the meaning of a source requirement", () => {
  // Requirements the old normalizer rewrote: split at "and write" (losing
  // "only inside" from the first half), split at "and send" (losing "only
  // through an interface" from the input half), and a "before ..." qualifier
  // hoisted into a weaker WHEN trigger.
  const SOURCE = `# Requirements Document

### Requirement 2: Transport

#### Acceptance Criteria

8. THE Client_Core SHALL receive user input from the Terminal_UI and send display output to the Terminal_UI only through an interface that a test can replace with a fake implementation.

### Requirement 18: Storage

#### Acceptance Criteria

12. WHERE a Data_Directory is configured, THE Chat_Server SHALL create and write files only inside the Data_Directory.

### Requirement 21: Display

#### Acceptance Criteria

1. THE Chat_Client SHALL pass every string received from the Chat_Server through the Display_Sanitizer before the Terminal_UI writes the string to the terminal.
`;

  let dir: string;
  let inputPath: string;
  let result: Awaited<ReturnType<typeof hardenMarkdownFile>>;
  let content: string;

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "spec-hardening-meaning-"));
    inputPath = join(dir, "requirements.md");
    await writeFile(inputPath, SOURCE, "utf-8");
    result = await hardenMarkdownFile(inputPath);
    content = await readFile(inputPath, "utf-8");
  });

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("keeps each requirement line verbatim", () => {
    for (const line of SOURCE.split("\n").filter((l) => /SHALL/.test(l))) {
      expect(content.split("\n")).toContain(line);
    }
  });

  it("adds no pattern tags and splits nothing", () => {
    expect(content).not.toMatch(/\[(?:Ubiquitous|Event-driven|Optional-feature|Complex)\]/);
    const shallLines = content.split("\n").filter((l) => /SHALL/.test(l) && !l.includes("[SECURITY:"));
    expect(shallLines).toHaveLength(3);
  });

  it("reports no EARS warnings for requirements that name a component as the actor", () => {
    expect(result!.sourceWarnings).toEqual([]);
  });

  it("labels requirements by their requirement and criterion number", async () => {
    const parsed = parseRequirementsFromMarkdown(content, inputPath).filter((r) => !r.constraint);
    expect(parsed.map((r) => r.label)).toEqual(["2.8", "18.12", "21.1"]);
  });
});

describe("incremental re-runs", () => {
  const SOURCE = `# Requirements Document

### Requirement 1: Search

#### Acceptance Criteria

1. WHEN a user submits a search query, THE SYSTEM SHALL return matching results from the database.
`;

  let dir: string;
  let inputPath: string;

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "spec-hardening-incremental-"));
    inputPath = join(dir, "requirements.md");
    await writeFile(inputPath, SOURCE, "utf-8");
    await hardenMarkdownFile(inputPath);
  });

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("hardens only a newly added requirement and keeps a reviewer's deletions", async () => {
    const hardened = await readFile(inputPath, "utf-8");
    // A reviewer deletes one constraint and the author adds a requirement.
    const firstConstraint = hardened.split("\n").find((l) => l.includes("[SECURITY:"))!;
    const curated = hardened
      .replace(`${firstConstraint}\n`, "")
      .replace(
        "### Requirement 1: Search",
        "### Requirement 2: Export\n\n#### Acceptance Criteria\n\n" +
          "1. WHEN a user requests a data export by their user identifier, THE SYSTEM SHALL fetch the account by id and return it.\n\n" +
          "### Requirement 1: Search"
      );
    await writeFile(inputPath, curated, "utf-8");

    const result = await hardenMarkdownFile(inputPath);
    const after = await readFile(inputPath, "utf-8");

    expect(result!.mode).toBe("incremental");
    expect(result!.report.results.map((r) => r.originalRequirement.id)).toEqual(["REQ-2.1"]);
    expect(after).not.toContain(firstConstraint);
    expect(after).toMatch(/^ {3}1\.1\. SEC-REQ-2\.1-/m);
    // Nothing the reviewer kept was changed.
    for (const line of curated.split("\n")) {
      if (!line.includes("spec-it-safe") && !/^[0-9a-f ]+$/.test(line)) {
        expect(after.split("\n")).toContain(line);
      }
    }
  });

  it("writes nothing in a dry run", async () => {
    const before = await readFile(inputPath, "utf-8");
    const changed = before.replace(
      "### Requirement 1: Search",
      "### Requirement 3: Lookup\n\n#### Acceptance Criteria\n\n" +
        "1. WHEN a user uploads a file, THE SYSTEM SHALL store the uploaded file in the upload directory.\n\n" +
        "### Requirement 1: Search"
    );
    await writeFile(inputPath, changed, "utf-8");

    const result = await hardenMarkdownFile(inputPath, { dryRun: true });

    expect(result!.dryRun).toBe(true);
    expect(result!.addedLines.length).toBeGreaterThan(0);
    expect(await readFile(inputPath, "utf-8")).toBe(changed);
  });
});

describe("files hardened by an older version", () => {
  const LEGACY = `# Requirements Document

### Requirement 1: Search

#### Acceptance Criteria

1. WHEN a user submits a search query, THE SYSTEM SHALL return matching results from the database.
   1.1. SEC-REQUIREMENTS-REQ-1-EC-89-1-1 [SECURITY: parameterized-query] THE SYSTEM SHALL execute all database queries using parameterized statements or prepared statements only.
`;

  let dir: string;
  let inputPath: string;

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "spec-hardening-legacy-"));
    inputPath = join(dir, "requirements.md");
    await writeFile(inputPath, LEGACY, "utf-8");
  });

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("leaves a file with no review record untouched", async () => {
    const result = await hardenMarkdownFile(inputPath);
    expect(result!.mode).toBe("unrecorded");
    expect(await readFile(inputPath, "utf-8")).toBe(LEGACY);
  });

  it("records the current requirements with markReviewed, adding only the marker", async () => {
    const result = await hardenMarkdownFile(inputPath, { markReviewed: true });
    const after = await readFile(inputPath, "utf-8");

    expect(result!.mode).toBe("marked");
    expect(after.startsWith(LEGACY.trimEnd())).toBe(true);
    expect(after).toContain("<!-- spec-it-safe:reviewed v1");

    const rerun = await hardenMarkdownFile(inputPath);
    expect(rerun!.mode).toBe("up-to-date");
  });
});

describe("section dedup, baseline subject and constraint checks", () => {
  const SOURCE = `# Requirements Document

The Chat_System is written in Go.

### Requirement 1: Rooms

#### Acceptance Criteria

1. WHEN a user submits a join request, THE Chat_System SHALL validate the room name.
2. WHEN a user submits a leave request, THE Room_Manager SHALL remove the user.
3. WHEN a user submits a kick request, THE Room_Manager SHALL remove the member.

### Requirement 2: File sharing

#### Acceptance Criteria

1. WHEN a user uploads a file, THE Message_Handler SHALL store the shared file.
2. WHEN a user uploads a file to a Chat_Room, THE Message_Handler SHALL announce the shared file.
`;

  let dir: string;
  let inputPath: string;
  let result: Awaited<ReturnType<typeof hardenMarkdownFile>>;
  let content: string;

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "spec-hardening-dedup-"));
    inputPath = join(dir, "requirements.md");
    await writeFile(inputPath, SOURCE, "utf-8");
    result = await hardenMarkdownFile(inputPath);
    content = await readFile(inputPath, "utf-8");
  });

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("writes a clause repeated within one requirement section only once", () => {
    const magicBytes = content.split("\n").filter((l) => l.includes("magic bytes"));
    expect(magicBytes).toHaveLength(1);
    expect(magicBytes[0]).toContain("SEC-REQ-2.1-");
    expect(result!.foldedDuplicates).toBeGreaterThan(0);
  });

  it("writes baseline constraints in the spec's system name", () => {
    const baseline = content.slice(content.indexOf("## Security Baseline"));
    expect(baseline).toMatch(/- SEC-BASELINE-1 \[SECURITY: [^\]]+\] .*THE Chat_System SHALL/);
    expect(baseline).not.toMatch(/- SEC-BASELINE-\d+ .*THE SYSTEM SHALL/);
  });

  it("reports malformed, unlabelled and duplicate hand-written constraint lines in check mode", async () => {
    const edited = content
      .replace(
        "1. WHEN a user uploads a file, THE Message_Handler SHALL store the shared file.\n",
        "1. WHEN a user uploads a file, THE Message_Handler SHALL store the shared file.\n" +
          "   1.9. SEC-REQ-2.1-SEM-434-1 [SECURITY: upload-storage-isolation] THE Message_Handler SHALL scope the file to the room and SHALL NOT mark it executable.\n" +
          "   1.10. [SECURITY: ownership-verification] THE Message_Handler SHALL serve the file only to Room_Members.\n" +
          "   1.11. SEC-REQ-2.1-SEM-434-1 [SECURITY: upload-storage-isolation] THE Message_Handler SHALL keep shared files out of the served directory.\n"
      );
    await writeFile(inputPath, edited, "utf-8");

    const checked = await hardenMarkdownFile(inputPath, { check: true });
    const messages = checked!.constraintWarnings.map((w) => `${w.constraintId}: ${w.message}`);

    expect(checked!.mode).toBe("checked");
    expect(await readFile(inputPath, "utf-8")).toBe(edited);
    expect(messages.some((m) => /SEM-434-1: .*compound/.test(m))).toBe(true);
    expect(messages.some((m) => /^\(no ID\): has no constraint ID/.test(m))).toBe(true);
    expect(messages.filter((m) => /reuses ID SEC-REQ-2\.1-SEM-434-1/.test(m))).toHaveLength(2);
    expect(checked!.constraintWarnings.every((w) => w.location.startsWith("2.1 (line"))).toBe(true);
  });

  it("also reports malformed constraint lines when the file is otherwise up to date", async () => {
    const rerun = await hardenMarkdownFile(inputPath);
    expect(rerun!.mode).toBe("up-to-date");
    expect(rerun!.constraintWarnings.length).toBeGreaterThan(0);
  });
});
