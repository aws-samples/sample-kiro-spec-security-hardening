import {
  atomizeTemplate,
  normalizeEARSClause,
  validateEARSClause,
  classifyEARSPattern,
} from "./ears-normalizer.js";
import type { EARSPattern } from "../types/index.js";

/**
 * Strict EARS enforcement for *source* requirements.
 *
 * `ears-normalizer` governs the clauses this library generates. This module
 * governs the clauses it is given: the hand-authored requirements in a spec,
 * which arrive with their own defects — lowercase keywords, a `[Event-driven]`
 * annotation ahead of the text, and compound responses joining two obligations
 * with a bare `and`.
 *
 * The two cases differ in one way that matters. A generated clause that cannot
 * be repaired is a library bug, so it is rejected. A source clause that cannot
 * be repaired is the user's text, so it is passed through with a warning: a
 * hardening tool that silently discards a requirement it failed to parse is far
 * more dangerous than one that reports it could not normalize it.
 *
 * Splitting a compound requirement changes its identity, so each part is
 * suffixed — REQ-F-015 becomes REQ-F-015a and REQ-F-015b. Suffixing rather than
 * renumbering keeps the original ID a resolvable prefix, so traceability records
 * that map REQ-F-015 to an upstream rule still resolve.
 */

/** A requirement ID and its EARS pattern annotation, as written in the source. */
const REQUIREMENT_PREFIX = /^([A-Z][\w-]*-[\w-]*\d+)\s*:\s*(?:\[([^\]]+)\]\s*)?/;

/**
 * Verbs that begin a genuine second obligation.
 *
 * Source prose rarely repeats `shall` on a second obligation ("shall compute X
 * and update Y"), so the `AND SHALL` rule in `ears-normalizer` never fires on it.
 * Restricting the split to a known verb set is what keeps "account ID, current
 * balance, and confirmation" — a noun list — from being mistaken for one.
 */
const OBLIGATION_VERBS = new Set([
  "compute", "update", "write", "read", "display", "redisplay", "clear",
  "return", "send", "store", "record", "create", "delete", "modify",
  "validate", "verify", "reject", "accept", "log", "emit", "alert",
  "invalidate", "issue", "apply", "enforce", "block", "flag", "notify",
  "set", "add", "remove", "insert", "post", "transfer", "increment",
  "decrement", "format", "populate", "initialize", "reset", "commit",
  "roll", "abort", "retry", "queue", "dispatch", "route", "transition",
  "determine", "retrieve", "generate", "calculate", "append", "confirm",
  "release", "acquire", "lock", "unlock", "mask", "redact", "purge",
]);

export interface SourceWarning {
  requirementId: string;
  message: string;
}

export interface NormalizedRequirement {
  /** Suffixed when the source requirement split; otherwise the original ID. */
  id: string;
  /** The original, unsuffixed source ID — the traceability key. */
  sourceId: string;
  /** Strict-EARS requirement text, without the ID prefix or pattern tag. */
  text: string;
  /** Full rendered line: `<id>: [<Pattern>] <text>`. */
  rendered: string;
  earsPattern: EARSPattern;
  /** True when this requirement is one part of a split compound. */
  split: boolean;
}

export interface SourceNormalizationResult {
  requirements: NormalizedRequirement[];
  warnings: SourceWarning[];
}

/**
 * Renders an EARS pattern as the bracketed annotation used in the specs.
 *
 * Only the first word is capitalized — the existing specs write
 * `[Event-driven]`, not `[Event-Driven]`, and the tag is prose rather than a
 * structural keyword.
 */
function formatPatternTag(pattern: EARSPattern): string {
  return pattern.charAt(0).toUpperCase() + pattern.slice(1);
}

/**
 * Splits a source response clause into its separate obligations.
 *
 * Handles both the two-part form ("shall compute X and update Y") and the serial
 * form ("shall clear X, display Y, and redisplay Z"). Each part inherits the
 * subject and modal the source elides, so "and update the account record" becomes
 * "THE SYSTEM SHALL update the account record".
 *
 * Splitting is gated on `OBLIGATION_VERBS`, which is what separates a list of
 * obligations from a list of nouns: "clear all input fields (account ID, current
 * balance, and confirmation)" has a comma-and list inside it, but `confirmation`
 * is not an obligation verb, so the clause stays whole.
 */
function splitCompoundResponse(text: string): string[] {
  const shallMatch = text.match(/\b(shall|SHALL)\b/);
  if (!shallMatch?.index) return [text];

  const head = text.slice(0, shallMatch.index + shallMatch[0].length);
  const response = text.slice(shallMatch.index + shallMatch[0].length);

  const parts = splitObligations(response);
  if (parts.length <= 1) return [text];

  return parts.map((part) => `${head} ${part}`);
}

/**
 * Splits a response body at each boundary that begins a new obligation.
 *
 * A boundary is a comma or `and` followed by a known obligation verb. Scanning
 * for the verb — rather than splitting on punctuation and inspecting after — is
 * what keeps parenthesised noun lists and non-obligation subordinate clauses
 * intact.
 */
function splitObligations(response: string): string[] {
  const boundaries: Array<{ start: number; end: number }> = [];
  const pattern = /(,\s+and\s+|,\s+|\s+and\s+)(?=(?:also\s+)?(?:then\s+)?([a-z]+))/g;

  let match: RegExpExecArray | null;
  while ((match = pattern.exec(response)) !== null) {
    const verb = match[2];
    if (!OBLIGATION_VERBS.has(verb.toLowerCase())) continue;

    // Never split inside a parenthesised aside — "(account ID, current balance,
    // and confirmation)" is one field list belonging to a single obligation.
    if (isInsideParentheses(response, match.index)) continue;

    boundaries.push({ start: match.index, end: match.index + match[1].length });
  }

  if (boundaries.length === 0) return [response.trim()];

  const parts: string[] = [];
  let cursor = 0;
  for (const boundary of boundaries) {
    parts.push(response.slice(cursor, boundary.start).trim());
    cursor = boundary.end;
  }
  parts.push(response.slice(cursor).trim());

  return parts.filter(Boolean);
}

/** True when `index` falls between an unclosed `(` and its `)`. */
function isInsideParentheses(text: string, index: number): boolean {
  let depth = 0;
  for (let i = 0; i < index; i++) {
    if (text[i] === "(") depth++;
    else if (text[i] === ")") depth = Math.max(0, depth - 1);
  }
  return depth > 0;
}

/**
 * Normalizes one source requirement line into one or more strict-EARS
 * requirements.
 *
 * `line` is the requirement text as written, including its `REQ-x:` prefix and
 * any `[Pattern]` annotation. Both are stripped, the body is normalized, and the
 * prefix is rebuilt from the pattern actually detected — a source tagged
 * `[Event-driven]` whose text is ubiquitous gets a corrected tag rather than the
 * one it claimed.
 */
export function normalizeSourceRequirement(line: string): SourceNormalizationResult {
  const warnings: SourceWarning[] = [];
  const prefixMatch = line.match(REQUIREMENT_PREFIX);
  const sourceId = prefixMatch?.[1] ?? "";
  const body = prefixMatch ? line.slice(prefixMatch[0].length).trim() : line.trim();

  // Sentence- and conjunction-level atomization, shared with the generated path,
  // then the source-only bare-`and` split.
  const atoms = atomizeTemplate(body).flatMap((atom) => splitCompoundResponse(atom));
  const multi = atoms.length > 1;

  const requirements = atoms.map((atom, index) => {
    const text = normalizeEARSClause(atom);
    const validation = validateEARSClause(text);
    const pattern = validation.pattern ?? classifyEARSPattern(text) ?? "ubiquitous";

    // Suffix only on a genuine split, so an unsplit requirement keeps its ID.
    // A requirement written as a bare numbered list item has no ID to suffix;
    // its list number is its identity and lives outside the text.
    const id = multi && sourceId
      ? `${sourceId}${String.fromCharCode(97 + index)}`
      : sourceId;

    if (!validation.valid) {
      warnings.push({
        requirementId: id,
        message: `source requirement is not strict EARS: ${validation.errors.join("; ")}`,
      });
    }

    return {
      id,
      sourceId,
      text,
      // Omit the `ID:` prefix entirely when the source had none, rather than
      // emitting a bare separator.
      rendered: id
        ? `${id}: [${formatPatternTag(pattern)}] ${text}`
        : `[${formatPatternTag(pattern)}] ${text}`,
      earsPattern: pattern,
      split: multi,
    };
  });

  if (multi) {
    warnings.push({
      requirementId: sourceId,
      message: `compound requirement split into ${requirements.length} atomic requirements (${requirements
        .map((r) => r.id)
        .join(", ")})`,
    });
  }

  return { requirements, warnings };
}
