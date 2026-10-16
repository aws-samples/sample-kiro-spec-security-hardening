import { readFile, writeFile, readdir, stat, unlink } from "node:fs/promises";
import { resolve, basename, dirname, join, extname } from "node:path";
import { HardeningEngine } from "../engine/hardening-engine.js";
import type { HardeningOptions } from "../engine/hardening-engine.js";
import type { ProposedRequirement } from "../types/index.js";
import type { AnchorWarning } from "../engine/anchor-checker.js";
import {
  normalizeSourceRequirement,
  type SourceWarning,
} from "../engine/source-normalizer.js";
import type {
  Requirement,
  EARSPattern,
  HardeningReport,
  SemanticCandidate,
} from "../types/index.js";

export interface ParsedRequirement {
  id: string;
  text: string;
  /**
   * The requirement as written, with the list marker and `[SECURITY: ...]` tag
   * removed but its `REQ-x:` prefix and `[Pattern]` tag intact. Held separately
   * from `text` so that source normalization keeps working if `text` is ever
   * narrowed to the bare response for trigger detection.
   */
  rawText: string;
  earsPattern: EARSPattern;
  /** Primitives named by a leading `[SECURITY: ...]` tag, if present. */
  securityAnnotations?: string[];
  /** Index of the first line of this requirement in the source file. */
  lineStart: number;
  /** Index of the last line of this requirement in the source file. */
  lineEnd: number;
  /** Leading whitespace of the requirement's first line. */
  indent: string;
  /** True when the requirement is written as a markdown ordered-list item. */
  numbered: boolean;
}

export interface HardenFileResult {
  inputPath: string;
  /**
   * Where the curated spec was written. Equal to `inputPath`: hardening edits the
   * requirements file in place rather than emitting sidecar files.
   */
  outputPath: string;
  requirementsFound: number;
  /** Cross-cutting constraints lifted into the single Security Baseline section. */
  baselineConstraints: number;
  /** Stale sidecar artifacts from an older two-file run that were removed. */
  removedArtifacts: string[];
  /**
   * True when the file was left untouched because it is already hardened.
   * Hardening output does not round-trip cleanly back through the parser, so
   * re-processing it in place would corrupt it; the file is skipped instead.
   */
  skipped: boolean;
  report: HardeningReport;
  /** Source requirements that were split or could not be made strict EARS. */
  sourceWarnings: SourceWarning[];
  /** Constraints anchored to a requirement whose trigger cannot enforce them. */
  anchorWarnings: AnchorWarning[];
  /**
   * Sub-threshold CWEs surfaced for agentic adjudication rather than applied to
   * the file. Never written into the spec by the deterministic pass; the agent
   * confirms and domain-specializes them (see the harden-spec skill).
   */
  semanticCandidates: SemanticCandidate[];
}

function detectEARSPattern(text: string): EARSPattern {
  const upper = text.toUpperCase();
  const hasWhen = /\bWHEN\b/.test(upper);
  const hasWhile = /\bWHILE\b/.test(upper);
  const hasIf = /\bIF\b/.test(upper);
  const hasShall = /\bSHALL\b/.test(upper);

  if (hasWhen && (hasWhile || hasIf) && hasShall) return "complex";
  if (hasWhen && hasShall) return "event-driven";
  if (hasWhile && hasShall) return "state-driven";
  if (hasIf && hasShall) return "unwanted-behavior";
  if (hasShall) return "ubiquitous";
  return "ubiquitous";
}

/**
 * Start of a markdown list item: a bullet, a plain enumerator (`2.`), or a
 * dotted sub-enumerator (`2.1.`) as emitted under a hardened requirement.
 */
const LIST_ITEM_START = /^\s*(?:[-*]|\d+(?:\.\d+)*\.)\s+/;

function stripListMarker(text: string): string {
  return text.replace(LIST_ITEM_START, "");
}

/**
 * Splits a leading `[SECURITY: primitive, ...]` tag off a requirement, so that
 * re-parsing a previously hardened file recognises its own annotations instead
 * of re-proposing constraints that are already present.
 *
 * An emitted constraint line carries its proposal ID ahead of the tag
 * (`SEC-REQ-1-EC-862-1 [SECURITY: ...] THE SYSTEM SHALL ...`), so that optional
 * ID is consumed too. Without it the tag no longer sits at offset zero and the
 * annotation goes unrecognised, which would make every re-run re-propose
 * constraints the document already states.
 */
function extractSecurityAnnotations(text: string): {
  text: string;
  securityAnnotations?: string[];
} {
  const match = text.match(/^(?:SEC-[\w-]+\s+)?\[SECURITY:\s*([^\]]+)\]\s*/i);
  if (!match) return { text };

  return {
    text: text.slice(match[0].length).trim(),
    securityAnnotations: match[1]
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean),
  };
}

/**
 * A line the author labelled with a requirement ID (`REQ-SEC-011:`) and wrote a
 * `SHALL` into is a requirement, whatever shape its grammar takes.
 *
 * This is deliberately looser than the pattern checks below. A line such as
 * "REQ-SEC-N-001: All payment operations shall be logged ..." names no actor and
 * carries no trigger keyword, so the structural checks miss it — and a miss here
 * is silent: the line is copied to the output neither normalized, hardened, nor
 * warned about. Recognizing it means it is at least reported as non-strict.
 */
const LABELLED_REQUIREMENT = /^[A-Z][\w-]*-[\w-]*\d+[a-z]?\s*:/;

function looksLikeEARSRequirement(text: string): boolean {
  const upper = text.toUpperCase();
  if (!/\bSHALL\b/.test(upper)) return false;

  return (
    LABELLED_REQUIREMENT.test(text) ||
    /\bWHEN\b/.test(upper) ||
    /\bWHILE\b/.test(upper) ||
    /\bIF\b/.test(upper) ||
    /\bTHE\s+(SYSTEM|[\w]+)\s+SHALL\b/.test(upper)
  );
}

export function parseRequirementsFromMarkdown(content: string, filePath: string): ParsedRequirement[] {
  const requirements: ParsedRequirement[] = [];
  const lines = content.split("\n");
  const fileBase = basename(filePath, extname(filePath)).replace(/\s+/g, "-").toUpperCase();

  let reqCounter = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.match(/^#{1,4}\s+(.+)/)) {
      continue;
    }

    const numberedMatch = line.match(/^\s*(\d+(?:\.\d+)*)\.\s+(.+)/);
    if (numberedMatch) {
      let text = numberedMatch[2].trim();
      let j = i + 1;
      while (j < lines.length) {
        const nextLine = lines[j];
        if (nextLine.match(LIST_ITEM_START) || nextLine.match(/^#{1,4}\s+/) || nextLine.trim() === "") break;
        if (nextLine.match(/^\s+\S/)) {
          text += " " + nextLine.trim();
          j++;
        } else {
          break;
        }
      }

      const numbered = extractSecurityAnnotations(text);

      if (looksLikeEARSRequirement(numbered.text)) {
        reqCounter++;
        requirements.push({
          id: `${fileBase}-REQ-${reqCounter}`,
          text: numbered.text,
          rawText: numbered.text,
          earsPattern: detectEARSPattern(numbered.text),
          securityAnnotations: numbered.securityAnnotations,
          lineStart: i,
          lineEnd: j - 1,
          indent: line.match(/^\s*/)?.[0] ?? "",
          numbered: true,
        });
      }
      continue;
    }

    const trimmed = line.trim();
    const bare = extractSecurityAnnotations(stripListMarker(trimmed));
    if (trimmed && looksLikeEARSRequirement(bare.text) && !line.startsWith("#")) {
      let text = bare.text;
      let j = i + 1;
      while (j < lines.length) {
        const nextLine = lines[j];
        if (nextLine.trim() === "" || nextLine.match(/^#{1,4}\s+/) || nextLine.match(LIST_ITEM_START)) break;
        text += " " + nextLine.trim();
        j++;
      }

      reqCounter++;
      requirements.push({
        id: `${fileBase}-REQ-${reqCounter}`,
        text,
        rawText: text,
        earsPattern: detectEARSPattern(text),
        securityAnnotations: bare.securityAnnotations,
        lineStart: i,
        lineEnd: j - 1,
        indent: line.match(/^\s*/)?.[0] ?? "",
        numbered: false,
      });
    }
  }

  return requirements;
}

/**
 * A cross-cutting constraint: the same security clause proposed under several
 * requirements. Lifted into one baseline statement rather than repeated inline.
 */
interface BaselineConstraint {
  id: string;
  text: string;
  securityPrimitives: string[];
  addressesCWEs: string[];
}

/**
 * Number of distinct requirements a clause must be proposed under before it is
 * treated as cross-cutting. Clauses like "execute all database queries using
 * parameterized statements" or "require a valid authenticated session" attach to
 * nearly every requirement; repeating them under each is the noise this curation
 * removes. Three is the smallest count that still means "most requirements" for a
 * typical small spec while never lifting a genuinely one-off constraint.
 */
const BASELINE_MIN_REQUIREMENTS = 3;

/**
 * Partitions proposals into cross-cutting and requirement-specific.
 *
 * Grouping is by exact clause text, not by primitive: contextual clauses that
 * share a primitive but name different triggers ("WHEN a user submits a search
 * query ...") stay inline where they belong, while the identical ubiquitous
 * clauses that repeat verbatim get lifted once. Returns the normalized clause
 * keys to suppress inline and the ordered baseline constraints to emit, keyed in
 * first-appearance order so the baseline reads top-down like the spec.
 */
function computeBaseline(report: HardeningReport): {
  suppressed: Set<string>;
  constraints: BaselineConstraint[];
} {
  const byClause = new Map<
    string,
    { requirementIds: Set<string>; proposal: ProposedRequirement }
  >();

  for (const result of report.results) {
    for (const proposal of result.proposedRequirements) {
      const key = proposal.text.trim().toLowerCase();
      let entry = byClause.get(key);
      if (!entry) {
        entry = { requirementIds: new Set(), proposal };
        byClause.set(key, entry);
      }
      entry.requirementIds.add(result.originalRequirement.id);
    }
  }

  const suppressed = new Set<string>();
  const constraints: BaselineConstraint[] = [];

  for (const [key, entry] of byClause) {
    if (entry.requirementIds.size < BASELINE_MIN_REQUIREMENTS) continue;
    suppressed.add(key);
    constraints.push({
      id: `SEC-BASELINE-${constraints.length + 1}`,
      text: entry.proposal.text,
      securityPrimitives: entry.proposal.securityPrimitives,
      addressesCWEs: entry.proposal.addressesCWEs,
    });
  }

  return { suppressed, constraints };
}

/**
 * Renders the final requirement set with every statement in strict EARS form.
 *
 * The source layout — headings, blank lines, prose, bullet lists — is preserved,
 * but each requirement *line* is replaced by its normalized form: canonical
 * uppercase keywords, one obligation per requirement, and a corrected pattern
 * tag. A compound source requirement expands into suffixed parts
 * (REQ-F-015 -> REQ-F-015a, REQ-F-015b), each on its own line.
 *
 * Security constraints are nested beneath the requirement they harden, carrying
 * their proposal ID so a reviewer can trace a clause back to the CWE report.
 * When a parent splits, the constraints attach to the *last* part, which is the
 * one holding the state mutation they guard.
 */
/**
 * The system-name subject a requirement addresses, taken from its `THE <name>
 * SHALL` clause — e.g. `Cron_SDK` in "…, THE Cron_SDK SHALL verify ownership".
 *
 * Returns undefined for the canonical `THE SYSTEM` (nothing to rewrite) and when
 * no subject is found. Inline constraints adopt this name so a hardening line
 * reads in the spec's own voice and stays traceable to the component it guards.
 */
function extractComponent(text: string): string | undefined {
  const match = text.match(/\bTHE\s+([A-Za-z][\w-]*)\s+SHALL\b/i);
  if (!match) return undefined;
  return /^system$/i.test(match[1]) ? undefined : match[1];
}

/**
 * Rewrites the canonical `THE SYSTEM` subject of a generated clause to the
 * spec's component name. Applied only at render time: the engine validates and
 * the baseline dedup keys on the canonical `THE SYSTEM` form, so the substitution
 * must not reach either.
 */
function applyComponentSubject(text: string, component: string | undefined): string {
  return component ? text.replace(/\bTHE SYSTEM\b/g, `THE ${component}`) : text;
}

function formatCuratedRequirementsMarkdown(
  sourceContent: string,
  requirements: ParsedRequirement[],
  report: HardeningReport,
  suppressed: Set<string>,
  baseline: BaselineConstraint[]
): { content: string; warnings: SourceWarning[] } {
  const proposalsById = new Map(
    report.results.map((r) => [r.originalRequirement.id, r.proposedRequirements])
  );

  const lines = sourceContent.split("\n");
  const warnings: SourceWarning[] = [];

  // Replacement text keyed by the line span it covers, so the rebuild below can
  // skip continuation lines of a requirement that wrapped.
  const replacements = new Map<number, { through: number; lines: string[] }>();

  for (const requirement of requirements) {
    const proposals = proposalsById.get(requirement.id) ?? [];
    const sourceLine = lines[requirement.lineStart];

    // The source line minus its list marker, which is re-attached after
    // normalization so numbering and indentation survive.
    const marker = sourceLine.match(LIST_ITEM_START)?.[0] ?? "";
    const parentNumber = requirement.numbered
      ? sourceLine.match(/^\s*(\d+)\./)?.[1]
      : undefined;

    const normalized = normalizeSourceRequirement(requirement.rawText);
    warnings.push(...normalized.warnings);

    const rendered: string[] = normalized.requirements.map((part, index) =>
      // Only the first part keeps the original marker; later parts align under
      // it, since re-using the marker would restart the source's numbering.
      index === 0
        ? `${marker}${part.rendered}`
        : `${requirement.indent}${" ".repeat(marker.length - requirement.indent.length)}${part.rendered}`
    );

    // Cross-cutting clauses are dropped here — they surface once in the baseline
    // section instead, so only requirement-specific constraints nest inline.
    const inlineProposals = proposals.filter(
      (p) => !suppressed.has(p.text.trim().toLowerCase())
    );

    if (inlineProposals.length > 0) {
      // Inline constraints adopt the parent's subject (e.g. `THE Cron_SDK
      // SHALL`) so they read in the spec's own voice and stay traceable to the
      // component they guard. The generic `THE SYSTEM` is left alone.
      const component = extractComponent(requirement.rawText);
      const childIndent = `${requirement.indent}   `;
      for (const [index, proposal] of inlineProposals.entries()) {
        const label = parentNumber ? `${parentNumber}.${index + 1}.` : "-";
        const tag = `[SECURITY: ${proposal.securityPrimitives.join(", ")}]`;
        const text = applyComponentSubject(proposal.text, component);
        rendered.push(`${childIndent}${label} ${proposal.id} ${tag} ${text}`);
      }
    }

    replacements.set(requirement.lineStart, {
      through: requirement.lineEnd,
      lines: rendered,
    });
  }

  const output: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const replacement = replacements.get(i);
    if (replacement) {
      output.push(...replacement.lines);
      i = replacement.through;
      continue;
    }
    output.push(lines[i]);
  }

  if (baseline.length > 0) {
    // Trim trailing blank lines so the appended section attaches cleanly
    // regardless of how the source file ended.
    while (output.length > 0 && output[output.length - 1].trim() === "") {
      output.pop();
    }
    output.push("");
    output.push("## Security Baseline (Cross-Cutting)");
    output.push("");
    output.push(
      "These constraints apply to every requirement above. They are stated once " +
        "here rather than repeated under each requirement."
    );
    output.push("");
    for (const constraint of baseline) {
      const tag = `[SECURITY: ${constraint.securityPrimitives.join(", ")}]`;
      output.push(`- ${constraint.id} ${tag} ${constraint.text}`);
    }
    output.push("");
  }

  return { content: output.join("\n"), warnings };
}

/**
 * Sidecar files an older two-file run may have left next to `inputPath`:
 * `<base>_hardened.md` (the report) and the final requirement list
 * (`final_requirements.md` for `requirements.md`, else `<base>_final_requirements.md`).
 * Curated hardening writes in place, so these are removed to avoid stale copies
 * lingering beside the source they no longer match.
 */
async function removeStaleArtifacts(inputPath: string): Promise<string[]> {
  const dir = dirname(inputPath);
  const base = basename(inputPath, ".md");
  const candidates = [
    join(dir, `${base}_hardened.md`),
    base.toLowerCase() === "requirements"
      ? join(dir, "final_requirements.md")
      : join(dir, `${base}_final_requirements.md`),
  ];

  const removed: string[] = [];
  for (const candidate of candidates) {
    try {
      await unlink(candidate);
      removed.push(candidate);
    } catch {
      // Absent is the common case; nothing to clean up.
    }
  }
  return removed;
}

/**
 * Hardens one requirements file, editing it in place.
 *
 * The source layout is preserved; requirement lines are normalized to strict
 * EARS, requirement-specific constraints are nested beneath the requirement they
 * guard, and cross-cutting constraints are consolidated into a single Security
 * Baseline section. Because every added line is valid EARS carrying a
 * `[SECURITY: ...]` tag, re-running is idempotent — already-stated constraints
 * are recognized and not re-proposed.
 */
/**
 * True when the file already carries hardening output — inline `[SECURITY: ...]`
 * constraints or the baseline section. Such a file is skipped: its EARS-split
 * requirement lines and injected constraints do not round-trip back through the
 * parser, so re-hardening in place would corrupt rather than extend it.
 */
function isAlreadyHardened(content: string): boolean {
  return (
    content.includes("[SECURITY:") ||
    content.includes("## Security Baseline (Cross-Cutting)")
  );
}

function emptyReport(reqs: Requirement[]): HardeningReport {
  return {
    timestamp: new Date().toISOString(),
    inputRequirements: reqs,
    results: [],
    summary: {
      totalRequirements: reqs.length,
      requirementsWithGaps: 0,
      totalCWEsTriggered: 0,
      totalProposedAdditions: 0,
      criticalGaps: 0,
      overallSecurityScore: 1,
    },
  };
}

async function curateInPlace(
  filePath: string,
  content: string,
  requirements: ParsedRequirement[],
  engine: HardeningEngine,
  options?: HardeningOptions
): Promise<HardenFileResult> {
  const reqs: Requirement[] = requirements.map((r) => ({
    id: r.id,
    text: r.text,
    earsPattern: r.earsPattern,
    securityAnnotations: r.securityAnnotations,
  }));

  if (isAlreadyHardened(content)) {
    return {
      inputPath: filePath,
      outputPath: filePath,
      requirementsFound: requirements.length,
      baselineConstraints: 0,
      removedArtifacts: [],
      skipped: true,
      report: emptyReport(reqs),
      sourceWarnings: [],
      anchorWarnings: [],
      semanticCandidates: [],
    };
  }

  const report = engine.harden(reqs, options);
  const { suppressed, constraints } = computeBaseline(report);
  const curated = formatCuratedRequirementsMarkdown(
    content,
    requirements,
    report,
    suppressed,
    constraints
  );

  await writeFile(filePath, curated.content, "utf-8");
  const removedArtifacts = await removeStaleArtifacts(filePath);

  return {
    inputPath: filePath,
    outputPath: filePath,
    requirementsFound: requirements.length,
    baselineConstraints: constraints.length,
    removedArtifacts,
    skipped: false,
    report,
    sourceWarnings: curated.warnings,
    anchorWarnings: engine.getAnchorWarnings(),
    semanticCandidates: engine.getSemanticCandidates(),
  };
}

export async function hardenMarkdownFile(
  filePath: string,
  options?: HardeningOptions
): Promise<HardenFileResult | null> {
  const resolved = resolve(filePath);
  const content = await readFile(resolved, "utf-8");
  const requirements = parseRequirementsFromMarkdown(content, resolved);

  if (requirements.length === 0) return null;

  const engine = new HardeningEngine();
  return curateInPlace(resolved, content, requirements, engine, options);
}

async function collectMarkdownFiles(dir: string): Promise<string[]> {
  const found: string[] = [];
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      found.push(...await collectMarkdownFiles(full));
    } else if (
      entry.isFile() &&
      entry.name.endsWith(".md") &&
      !entry.name.endsWith("_hardened.md") &&
      !entry.name.endsWith("final_requirements.md")
    ) {
      found.push(full);
    }
  }
  return found;
}

export async function hardenMarkdownFiles(
  inputs: string[],
  options?: HardeningOptions
): Promise<HardenFileResult[]> {
  const files: string[] = [];

  for (const input of inputs) {
    const resolved = resolve(input);
    const info = await stat(resolved);

    if (info.isDirectory()) {
      files.push(...await collectMarkdownFiles(resolved));
    } else if (info.isFile() && resolved.endsWith(".md")) {
      files.push(resolved);
    }
  }

  const results: HardenFileResult[] = [];
  const engine = new HardeningEngine();

  for (const filePath of files) {
    const content = await readFile(filePath, "utf-8");
    const requirements = parseRequirementsFromMarkdown(content, filePath);

    if (requirements.length === 0) continue;

    results.push(
      await curateInPlace(filePath, content, requirements, engine, options)
    );
  }

  return results;
}
