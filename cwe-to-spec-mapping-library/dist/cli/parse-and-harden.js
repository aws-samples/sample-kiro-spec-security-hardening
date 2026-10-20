import { createHash } from "node:crypto";
import { readFile, writeFile, readdir, stat, unlink } from "node:fs/promises";
import { resolve, basename, dirname, join, extname } from "node:path";
import { HardeningEngine } from "../engine/hardening-engine.js";
import { detectSpecContext } from "../engine/spec-context.js";
import { validateConstraintStatement, validateSourceRequirement, } from "../engine/source-normalizer.js";
function detectEARSPattern(text) {
    const upper = text.toUpperCase();
    const hasWhen = /\bWHEN\b/.test(upper);
    const hasWhile = /\bWHILE\b/.test(upper);
    const hasIf = /\bIF\b/.test(upper);
    const hasShall = /\bSHALL\b/.test(upper);
    if (hasWhen && (hasWhile || hasIf) && hasShall)
        return "complex";
    if (hasWhen && hasShall)
        return "event-driven";
    if (hasWhile && hasShall)
        return "state-driven";
    if (hasIf && hasShall)
        return "unwanted-behavior";
    return "ubiquitous";
}
/**
 * Start of a markdown list item: a bullet, a plain enumerator (`2.`), or a
 * dotted sub-enumerator (`2.1.`) as emitted under a hardened requirement.
 */
const LIST_ITEM_START = /^\s*(?:[-*]|\d+(?:\.\d+)*\.)\s+/;
function stripListMarker(text) {
    return text.replace(LIST_ITEM_START, "");
}
/**
 * Splits a leading `[SECURITY: primitive, ...]` tag, and the proposal ID ahead
 * of it (`SEC-12.3-EC-862-1 [SECURITY: ...]`), off a line.
 */
function extractSecurityAnnotations(text) {
    const match = text.match(/^(?:SEC-[\w.-]+\s+)?\[SECURITY:\s*([^\]]+)\]\s*/i);
    if (!match)
        return { text };
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
 * `SHALL` into is a requirement, whatever shape its grammar takes — recognizing
 * it means it is at least reported when it is not strict EARS.
 */
const LABELLED_REQUIREMENT = /^[A-Z][\w-]*-[\w-]*\d+[a-z]?\s*:/;
/** The author's own requirement ID, when the line starts with one. */
const AUTHOR_ID = /^([A-Z][\w-]*-[\w-]*\d+[a-z]?)\s*:/;
function looksLikeEARSRequirement(text) {
    const upper = text.toUpperCase();
    if (!/\bSHALL\b/.test(upper))
        return false;
    return (LABELLED_REQUIREMENT.test(text) ||
        /\bWHEN\b/.test(upper) ||
        /\bWHILE\b/.test(upper) ||
        /\bIF\b/.test(upper) ||
        /\bTHE\s+(SYSTEM|[\w]+)\s+SHALL\b/.test(upper));
}
const BASELINE_HEADING = "## Security Baseline (Cross-Cutting)";
/** A Kiro requirement heading: "### Requirement 12: Chat messages". */
const REQUIREMENT_HEADING = /^(#{1,6})\s+Requirement\s+(\d+[\w.]*)\b/i;
/**
 * Record of the requirements already reviewed, as hashes of their text. Kept
 * in an HTML comment at the end of the file, which Markdown renderers hide.
 * It is what lets a re-run harden only requirements added or changed since,
 * without a pre-hardening copy of the spec.
 */
const REVIEW_MARKER = /<!--\s*spec-it-safe:reviewed\s+v1\b([\s\S]*?)-->/;
function requirementHash(text) {
    return createHash("sha256")
        .update(text.replace(/\s+/g, " ").trim())
        .digest("hex")
        .slice(0, 12);
}
function headingLevel(line) {
    return line.match(/^(#{1,6})\s/)?.[1].length ?? 0;
}
export function parseRequirementsFromMarkdown(content, filePath) {
    const requirements = [];
    const lines = content.split("\n");
    const fileBase = basename(filePath, extname(filePath)).replace(/\s+/g, "-").toUpperCase();
    const usedIds = new Set();
    let reqCounter = 0;
    let section;
    let inBaseline = false;
    const makeId = (label, rawText) => {
        reqCounter++;
        const authorId = rawText.match(AUTHOR_ID)?.[1];
        let id = authorId ?? (label ? `REQ-${label}` : `${fileBase}-REQ-${reqCounter}`);
        if (usedIds.has(id))
            id = `${id}-${reqCounter}`;
        usedIds.add(id);
        return id;
    };
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const level = headingLevel(line);
        if (level > 0) {
            const heading = line.match(REQUIREMENT_HEADING);
            if (heading) {
                section = { number: heading[2], level };
            }
            else if (section && level <= section.level) {
                section = undefined;
            }
            if (line.trim() === BASELINE_HEADING)
                inBaseline = true;
            else if (inBaseline && level <= 2)
                inBaseline = false;
            continue;
        }
        const numberedMatch = line.match(/^\s*(\d+(?:\.\d+)*)\.\s+(.+)/);
        if (numberedMatch) {
            let text = numberedMatch[2].trim();
            let j = i + 1;
            while (j < lines.length) {
                const nextLine = lines[j];
                if (nextLine.match(LIST_ITEM_START) || nextLine.match(/^#{1,6}\s+/) || nextLine.trim() === "")
                    break;
                if (nextLine.match(/^\s+\S/)) {
                    text += " " + nextLine.trim();
                    j++;
                }
                else {
                    break;
                }
            }
            const numbered = extractSecurityAnnotations(text);
            const isConstraint = Boolean(numbered.securityAnnotations) || inBaseline;
            if (looksLikeEARSRequirement(numbered.text)) {
                const itemNumber = numberedMatch[1];
                const label = isConstraint
                    ? `line ${i + 1}`
                    : section && !itemNumber.includes(".")
                        ? `${section.number}.${itemNumber}`
                        : undefined;
                requirements.push({
                    id: isConstraint ? `CONSTRAINT-L${i + 1}` : makeId(label, numbered.text),
                    text: numbered.text,
                    rawText: numbered.text,
                    earsPattern: detectEARSPattern(numbered.text),
                    securityAnnotations: numbered.securityAnnotations,
                    constraint: isConstraint || undefined,
                    label: label ?? `line ${i + 1}`,
                    section: section?.number,
                    inBaseline: inBaseline || undefined,
                    lineStart: i,
                    lineEnd: j - 1,
                    indent: line.match(/^\s*/)?.[0] ?? "",
                    numbered: true,
                });
            }
            i = j - 1;
            continue;
        }
        const trimmed = line.trim();
        const bare = extractSecurityAnnotations(stripListMarker(trimmed));
        if (trimmed && looksLikeEARSRequirement(bare.text)) {
            let text = bare.text;
            let j = i + 1;
            while (j < lines.length) {
                const nextLine = lines[j];
                if (nextLine.trim() === "" || nextLine.match(/^#{1,6}\s+/) || nextLine.match(LIST_ITEM_START))
                    break;
                text += " " + nextLine.trim();
                j++;
            }
            const isConstraint = Boolean(bare.securityAnnotations) || inBaseline;
            requirements.push({
                id: isConstraint ? `CONSTRAINT-L${i + 1}` : makeId(undefined, text),
                text,
                rawText: text,
                earsPattern: detectEARSPattern(text),
                securityAnnotations: bare.securityAnnotations,
                constraint: isConstraint || undefined,
                label: `line ${i + 1}`,
                section: section?.number,
                inBaseline: inBaseline || undefined,
                lineStart: i,
                lineEnd: j - 1,
                indent: line.match(/^\s*/)?.[0] ?? "",
                numbered: false,
            });
            i = j - 1;
        }
    }
    return requirements;
}
/**
 * Number of distinct requirements a clause must be proposed under before it is
 * treated as cross-cutting.
 */
const BASELINE_MIN_REQUIREMENTS = 3;
/** Comparison key for "the document already states this clause". */
function clauseKey(text) {
    return text.replace(/\s+/g, " ").trim().toLowerCase();
}
/**
 * Partitions proposals into cross-cutting and requirement-specific, by exact
 * clause text. `nextNumber` continues an existing baseline's numbering.
 */
function computeBaseline(report, nextNumber) {
    const byClause = new Map();
    for (const result of report.results) {
        for (const proposal of result.proposedRequirements) {
            const key = clauseKey(proposal.text);
            let entry = byClause.get(key);
            if (!entry) {
                entry = { requirementIds: new Set(), proposal };
                byClause.set(key, entry);
            }
            entry.requirementIds.add(result.originalRequirement.id);
        }
    }
    const suppressed = new Set();
    const constraints = [];
    for (const [key, entry] of byClause) {
        if (entry.requirementIds.size < BASELINE_MIN_REQUIREMENTS)
            continue;
        suppressed.add(key);
        constraints.push({
            id: `SEC-BASELINE-${nextNumber + constraints.length}`,
            text: entry.proposal.text,
            securityPrimitives: entry.proposal.securityPrimitives,
            addressesCWEs: entry.proposal.addressesCWEs,
        });
    }
    return { suppressed, constraints };
}
/**
 * The system-name subject a requirement addresses, taken from its `THE <name>
 * SHALL` clause — e.g. `Cron_SDK`. Undefined for the canonical `THE SYSTEM`.
 */
function extractComponent(text) {
    const match = text.match(/\bTHE\s+([A-Za-z][\w-]*)\s+SHALL\b/i);
    if (!match)
        return undefined;
    return /^system$/i.test(match[1]) ? undefined : match[1];
}
/**
 * Rewrites the canonical `THE SYSTEM` subject of a generated clause to the
 * spec's component name, so inline constraints read in the spec's own voice.
 */
function applyComponentSubject(text, component) {
    return component ? text.replace(/\bTHE SYSTEM\b/g, `THE ${component}`) : text;
}
/** The `THE <name> SHALL` subject of a statement, if it names one. */
function subjectOf(text) {
    return text.match(/\bTHE\s+([A-Za-z][\w-]*)\s+SHALL\b/i)?.[1];
}
function mostCommon(values) {
    const counts = new Map();
    for (const value of values)
        counts.set(value, (counts.get(value) ?? 0) + 1);
    return [...counts].sort((a, b) => b[1] - a[1])[0]?.[0];
}
/**
 * The subject baseline constraints are written in. Baseline lines apply to the
 * whole system, so they use the spec's own name for it rather than the
 * canonical `THE SYSTEM`:
 *
 *   1. the subject the existing baseline lines already use, so a section stays
 *      in one voice;
 *   2. otherwise a requirement subject named as the system (`Chat_System`);
 *   3. otherwise the one subject every requirement shares.
 *
 * Undefined (keep `THE SYSTEM`) when none applies, rather than picking one
 * component to speak for the whole system.
 */
function chooseBaselineSubject(parsed) {
    const named = (values) => values.filter((v) => Boolean(v) && !/^system$/i.test(v));
    const existing = named(parsed.filter((r) => r.constraint && r.inBaseline).map((r) => subjectOf(r.text)));
    if (existing.length > 0)
        return mostCommon(existing);
    const subjects = parsed.filter((r) => !r.constraint).map((r) => subjectOf(r.rawText));
    const systemNamed = named(subjects).filter((s) => /(?:^|[_-])system$/i.test(s));
    if (systemNamed.length > 0)
        return mostCommon(systemNamed);
    const distinct = new Set(subjects.filter(Boolean));
    if (distinct.size === 1)
        return named([...distinct])[0];
    return undefined;
}
/** A constraint line's ID: the token between its list marker and its tag. */
const CONSTRAINT_ID = /^\s*(?:[-*]|\d+(?:\.\d+)*\.)?\s*(\S+)\s+\[SECURITY:/i;
/**
 * Checks every `[SECURITY: ...]` line in the file. The engine validates the
 * constraints it generates, but lines a reviewer wrote or rewrote by hand pass
 * through no such gate, so they are checked here on every run.
 */
function checkConstraintLines(parsed, lines) {
    const warnings = [];
    const constraints = parsed.filter((r) => r.constraint && r.securityAnnotations);
    const parentOf = (r) => [...parsed].reverse().find((p) => !p.constraint && p.lineEnd < r.lineStart && p.section === r.section);
    const ids = new Map();
    for (const r of constraints) {
        const id = lines[r.lineStart].match(CONSTRAINT_ID)?.[1];
        if (id?.startsWith("SEC-"))
            ids.set(id, (ids.get(id) ?? 0) + 1);
    }
    for (const r of constraints) {
        const parent = r.inBaseline ? undefined : parentOf(r);
        const location = parent
            ? `${parent.label} (line ${r.lineStart + 1})`
            : `line ${r.lineStart + 1}`;
        const id = lines[r.lineStart].match(CONSTRAINT_ID)?.[1];
        const constraintId = id?.startsWith("SEC-") ? id : "(no ID)";
        const problems = [];
        if (!id?.startsWith("SEC-")) {
            problems.push("has no constraint ID — start it with SEC-<requirement>-<source>-<n>");
        }
        else if ((ids.get(id) ?? 0) > 1) {
            problems.push(`reuses ID ${id}, which another constraint line also has`);
        }
        problems.push(...validateConstraintStatement(r.text).errors);
        if (problems.length > 0) {
            warnings.push({ location, constraintId, message: problems.join("; ") });
        }
    }
    return warnings;
}
/** Lines of the review marker block, so they can be replaced as one unit. */
function findMarker(lines) {
    const start = lines.findIndex((line) => line.includes("<!-- spec-it-safe:reviewed"));
    if (start < 0)
        return undefined;
    let end = start;
    while (end < lines.length && !lines[end].includes("-->"))
        end++;
    const block = lines.slice(start, end + 1).join("\n");
    const body = block.match(REVIEW_MARKER)?.[1] ?? "";
    return { start, end, hashes: new Set(body.match(/[0-9a-f]{12}/g) ?? []) };
}
/**
 * Keeps recorded hashes in their existing order and appends new ones, so a
 * re-run changes only the marker's last rows.
 */
function renderMarker(hashes) {
    const ordered = [...new Set(hashes)];
    const rows = [];
    for (let i = 0; i < ordered.length; i += 8)
        rows.push(ordered.slice(i, i + 8).join(" "));
    return [
        "<!-- spec-it-safe:reviewed v1",
        "Requirements already hardened by Spec It Safe, as hashes of their text.",
        "A re-run hardens only requirements whose hash is missing here.",
        ...rows,
        "-->",
    ];
}
function insert(insertions, after, lines) {
    if (lines.length === 0)
        return;
    insertions.set(after, [...(insertions.get(after) ?? []), ...lines]);
}
/**
 * Applies insertions and the marker replacement, then proves the result keeps
 * every original line, unchanged and in order. Any failure is a defect in this
 * tool, so it throws instead of writing a file that changed the user's text.
 */
function applyInsertions(original, insertions, marker, markerLines) {
    const output = [];
    const added = [];
    const isMarkerLine = (i) => marker !== undefined && i >= marker.start && i <= marker.end;
    const emit = (after, lines) => {
        for (const text of lines) {
            output.push(text);
            added.push({ after: after + 1, text });
        }
    };
    emit(-1, insertions.get(-1) ?? []);
    for (let i = 0; i < original.length; i++) {
        if (!isMarkerLine(i))
            output.push(original[i]);
        emit(i, insertions.get(i) ?? []);
    }
    // Trailing blank lines of the original stay at the very end; the marker
    // follows the last content line.
    while (output.length > 0 && output[output.length - 1] === "")
        output.pop();
    const trailingNewline = original[original.length - 1] === "";
    output.push("", ...markerLines);
    if (trailingNewline)
        output.push("");
    let cursor = 0;
    for (let i = 0; i < original.length; i++) {
        if (isMarkerLine(i) || (original[i] === "" && i >= original.length - 1))
            continue;
        while (cursor < output.length && output[cursor] !== original[i])
            cursor++;
        if (cursor >= output.length) {
            throw new Error(`refusing to write: line ${i + 1} of the original would not be preserved unchanged`);
        }
        cursor++;
    }
    return { content: output.join("\n"), added };
}
/**
 * True when the file carries hardening output: inline `[SECURITY: ...]`
 * constraints, the baseline section, or the review marker.
 */
function isHardened(content) {
    return (content.includes("[SECURITY:") ||
        content.includes(BASELINE_HEADING) ||
        REVIEW_MARKER.test(content));
}
function emptyReport(reqs) {
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
/**
 * Sidecar files an older two-file run may have left next to `inputPath`.
 * Curated hardening writes in place, so these are removed to avoid stale
 * copies lingering beside the source they no longer match.
 */
async function removeStaleArtifacts(inputPath) {
    const dir = dirname(inputPath);
    const base = basename(inputPath, ".md");
    const candidates = [
        join(dir, `${base}_hardened.md`),
        base.toLowerCase() === "requirements"
            ? join(dir, "final_requirements.md")
            : join(dir, `${base}_final_requirements.md`),
    ];
    const removed = [];
    for (const candidate of candidates) {
        try {
            await unlink(candidate);
            removed.push(candidate);
        }
        catch {
            // Absent is the common case; nothing to clean up.
        }
    }
    return removed;
}
/**
 * Hardens one requirements file in place.
 *
 * Original lines are never changed, moved or removed: requirement-specific
 * `[SECURITY: ...]` constraints are inserted beneath the requirement they
 * guard, cross-cutting ones are added to a single Security Baseline section,
 * and a hidden review marker records which requirements were hardened. A
 * re-run hardens only requirements added or changed since — so no copy of the
 * pre-hardening spec is ever needed — and constraints a reviewer removed are
 * not proposed again for requirements already reviewed.
 */
async function curateInPlace(filePath, content, parsed, engine, options = {}) {
    const sources = parsed.filter((r) => !r.constraint);
    const reqs = parsed.map((r) => ({
        id: r.id,
        text: r.text,
        earsPattern: r.earsPattern,
        securityAnnotations: r.securityAnnotations,
    }));
    const lines = content.split("\n");
    const marker = findMarker(lines);
    const hashes = new Map(sources.map((r) => [r.id, requirementHash(r.rawText)]));
    const allHashes = [...(marker?.hashes ?? []), ...hashes.values()];
    const base = {
        inputPath: filePath,
        outputPath: filePath,
        requirementsFound: sources.length,
        removedArtifacts: [],
        dryRun: Boolean(options.dryRun),
        sourceWarnings: [],
        anchorWarnings: [],
        suppressedConstraints: [],
        specializationWarnings: [],
        constraintWarnings: checkConstraintLines(parsed, lines),
        foldedDuplicates: 0,
        semanticCandidates: [],
    };
    const untouched = (mode) => ({
        ...base,
        requirementsHardened: 0,
        baselineConstraints: 0,
        mode,
        skipped: true,
        addedLines: [],
        report: emptyReport(reqs),
    });
    const hardened = isHardened(content);
    const labelOf = (id) => {
        const r = parsed.find((p) => p.id === id);
        return r ? `${r.label} (line ${r.lineStart + 1})` : id;
    };
    const earsWarnings = (requirements) => requirements.flatMap((requirement) => {
        const validation = validateSourceRequirement(requirement.rawText);
        return validation.valid
            ? []
            : [{
                    requirementId: labelOf(requirement.id),
                    message: `source requirement is not strict EARS: ${validation.errors.join("; ")}`,
                }];
    });
    if (options.check) {
        return { ...untouched("checked"), skipped: false, sourceWarnings: earsWarnings(sources) };
    }
    if (options.markReviewed) {
        const result = applyInsertions(lines, new Map(), marker, renderMarker(allHashes));
        if (!options.dryRun)
            await writeFile(filePath, result.content, "utf-8");
        return { ...untouched("marked"), skipped: false, addedLines: result.added };
    }
    if (hardened && !marker)
        return untouched("unrecorded");
    const targets = sources.filter((r) => !marker?.hashes.has(hashes.get(r.id)));
    if (targets.length === 0)
        return untouched("up-to-date");
    const report = engine.harden(reqs, {
        ...options,
        specContext: options.specContext ?? detectSpecContext(content),
        targetRequirementIds: targets.map((r) => r.id),
    });
    // Clauses the document already states — inline or in the baseline, as added
    // by this tool or rewritten by a reviewer — are not added again.
    const existingClauses = new Set(parsed.filter((r) => r.constraint).map((r) => clauseKey(r.text)));
    const existingIds = new Set(content.match(/\bSEC-[\w.-]*\w/g) ?? []);
    const uniqueId = (id) => {
        let candidate = id;
        for (let n = 2; existingIds.has(candidate); n++)
            candidate = `${id}-${n}`;
        existingIds.add(candidate);
        return candidate;
    };
    const baselineNumbers = [...content.matchAll(/\bSEC-BASELINE-(\d+)\b/g)].map((m) => Number(m[1]));
    const { suppressed, constraints } = computeBaseline(report, Math.max(0, ...baselineNumbers) + 1);
    const baselineSubject = chooseBaselineSubject(parsed);
    const newBaseline = constraints.filter((c) => !existingClauses.has(clauseKey(c.text)) &&
        !existingClauses.has(clauseKey(applyComponentSubject(c.text, baselineSubject))));
    const insertions = new Map();
    const byId = new Map(parsed.map((r) => [r.id, r]));
    // Proposal ID -> the ID of the line that states it in the file, so warnings
    // name lines a reader can find. Lifted clauses map to their baseline ID.
    const writtenIds = new Map();
    let hardenedCount = 0;
    // Within one "Requirement N" section, a clause proposed under several
    // criteria is written once, under the first. The criteria of a section
    // describe one feature, so repeating the same upload or error-handling block
    // under each adds nothing. Clause key -> the ID it was written under.
    const writtenInSection = new Map();
    let foldedDuplicates = 0;
    for (const result of report.results) {
        const requirement = byId.get(result.originalRequirement.id);
        const component = extractComponent(requirement.rawText);
        const sectionClauses = requirement.section
            ? writtenInSection.get(requirement.section) ??
                writtenInSection.set(requirement.section, new Map()).get(requirement.section)
            : new Map();
        const inline = result.proposedRequirements.filter((p) => {
            if (suppressed.has(clauseKey(p.text)))
                return false;
            if (existingClauses.has(clauseKey(applyComponentSubject(p.text, component))))
                return false;
            const earlier = sectionClauses.get(clauseKey(p.text));
            if (earlier) {
                writtenIds.set(p.id, earlier);
                foldedDuplicates++;
                return false;
            }
            return true;
        });
        if (inline.length === 0)
            continue;
        hardenedCount++;
        // New constraints go after any the requirement already has.
        const children = childrenOf(parsed, requirement);
        const anchor = children.length > 0 ? children[children.length - 1].lineEnd : requirement.lineEnd;
        const sourceLine = lines[requirement.lineStart];
        const listMarker = sourceLine.match(LIST_ITEM_START)?.[0] ?? requirement.indent;
        const parentNumber = requirement.numbered ? sourceLine.match(/^\s*(\d+)\./)?.[1] : undefined;
        const childIndent = " ".repeat(Math.max(listMarker.length, requirement.indent.length + 3));
        insert(insertions, anchor, inline.map((proposal, index) => {
            const label = parentNumber ? `${parentNumber}.${children.length + index + 1}.` : "-";
            const tag = `[SECURITY: ${proposal.securityPrimitives.join(", ")}]`;
            const text = applyComponentSubject(proposal.text, component);
            const id = uniqueId(proposal.id);
            writtenIds.set(proposal.id, id);
            sectionClauses.set(clauseKey(proposal.text), id);
            return `${childIndent}${label} ${id} ${tag} ${text}`;
        }));
    }
    if (newBaseline.length > 0) {
        const baselineIds = new Map();
        const entries = newBaseline.map((c) => {
            const tag = `[SECURITY: ${c.securityPrimitives.join(", ")}]`;
            const id = uniqueId(c.id);
            baselineIds.set(clauseKey(c.text), id);
            return `- ${id} ${tag} ${applyComponentSubject(c.text, baselineSubject)}`;
        });
        for (const result of report.results) {
            for (const p of result.proposedRequirements) {
                const id = baselineIds.get(clauseKey(p.text));
                if (id)
                    writtenIds.set(p.id, id);
            }
        }
        const headingAt = lines.findIndex((l) => l.trim() === BASELINE_HEADING);
        if (headingAt >= 0) {
            // Append to the existing section, after its last non-blank line.
            let end = headingAt + 1;
            while (end < lines.length && headingLevel(lines[end]) === 0 && !lines[end].includes("<!-- spec-it-safe:reviewed"))
                end++;
            let last = end - 1;
            while (last > headingAt && lines[last].trim() === "")
                last--;
            insert(insertions, last, entries);
        }
        else {
            let last = lines.length - 1;
            while (last >= 0 && (lines[last].trim() === "" || (marker && last >= marker.start)))
                last--;
            insert(insertions, last, [
                "",
                BASELINE_HEADING,
                "",
                "These constraints apply to every requirement above. They are stated once " +
                    "here rather than repeated under each requirement.",
                "",
                ...entries,
            ]);
        }
    }
    const written = applyInsertions(lines, insertions, marker, renderMarker(allHashes));
    let removedArtifacts = [];
    if (!options.dryRun) {
        await writeFile(filePath, written.content, "utf-8");
        removedArtifacts = await removeStaleArtifacts(filePath);
    }
    const sourceWarnings = earsWarnings(targets);
    const specializationWarnings = [];
    const warnedIds = new Set();
    for (const result of report.results) {
        for (const p of result.proposedRequirements) {
            const id = writtenIds.get(p.id);
            if (!id || !p.genericSlots || warnedIds.has(id))
                continue;
            warnedIds.add(id);
            specializationWarnings.push({
                location: labelOf(result.originalRequirement.id),
                constraintId: id,
                message: `built with generic text ${p.genericSlots
                    .map((g) => `"${g.filledWith}" for {${g.slot}}`)
                    .join(", ")} because the requirement does not name one — ` +
                    `rewrite the constraint in this requirement's terms`,
            });
        }
    }
    return {
        ...base,
        removedArtifacts,
        requirementsHardened: hardenedCount,
        baselineConstraints: newBaseline.length,
        mode: marker ? "incremental" : "full",
        skipped: false,
        addedLines: written.added,
        report,
        sourceWarnings,
        specializationWarnings,
        foldedDuplicates,
        anchorWarnings: engine.getAnchorWarnings().flatMap((w) => {
            const ids = [
                ...new Set(w.constraintId
                    .split(", ")
                    .map((id) => writtenIds.get(id))
                    .filter((id) => Boolean(id))),
            ];
            // Nothing written (already stated in the document): nothing to review.
            if (ids.length === 0)
                return [];
            return [{ ...w, requirementId: labelOf(w.requirementId), constraintId: ids.join(", ") }];
        }),
        suppressedConstraints: engine
            .getSuppressedConstraints()
            .map((s) => ({ ...s, requirementId: labelOf(s.requirementId) })),
        semanticCandidates: engine.getSemanticCandidates(),
    };
}
/** The constraint lines directly beneath a requirement, in order. */
function childrenOf(parsed, requirement) {
    const children = [];
    let next = requirement.lineEnd + 1;
    for (const r of parsed) {
        if (r.lineStart < next)
            continue;
        if (r.lineStart !== next || !r.constraint)
            break;
        children.push(r);
        next = r.lineEnd + 1;
    }
    return children;
}
export async function hardenMarkdownFile(filePath, options) {
    const resolved = resolve(filePath);
    const content = await readFile(resolved, "utf-8");
    const requirements = parseRequirementsFromMarkdown(content, resolved);
    if (requirements.length === 0)
        return null;
    const engine = new HardeningEngine();
    return curateInPlace(resolved, content, requirements, engine, options);
}
async function collectMarkdownFiles(dir) {
    const found = [];
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) {
            found.push(...await collectMarkdownFiles(full));
        }
        else if (entry.isFile() &&
            entry.name.endsWith(".md") &&
            !entry.name.endsWith("_hardened.md") &&
            !entry.name.endsWith("final_requirements.md")) {
            found.push(full);
        }
    }
    return found;
}
export async function hardenMarkdownFiles(inputs, options) {
    const files = [];
    for (const input of inputs) {
        const resolved = resolve(input);
        const info = await stat(resolved);
        if (info.isDirectory()) {
            files.push(...await collectMarkdownFiles(resolved));
        }
        else if (info.isFile() && resolved.endsWith(".md")) {
            files.push(resolved);
        }
    }
    const results = [];
    const engine = new HardeningEngine();
    for (const filePath of files) {
        const content = await readFile(filePath, "utf-8");
        const requirements = parseRequirementsFromMarkdown(content, filePath);
        if (requirements.length === 0)
            continue;
        results.push(await curateInPlace(filePath, content, requirements, engine, options));
    }
    return results;
}
//# sourceMappingURL=parse-and-harden.js.map