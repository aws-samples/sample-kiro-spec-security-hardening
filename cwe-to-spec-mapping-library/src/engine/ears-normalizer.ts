import type { EARSPattern } from "../types/index.js";

/**
 * Strict EARS grammar enforcement.
 *
 * The library's constraint templates are authored for readability, which means
 * they may bundle several `SHALL` assertions into one string, and their trigger
 * clauses carry `{placeholder}` slots filled from the parent requirement. Neither
 * form is valid EARS on its own:
 *
 *   - EARS requires one requirement = one testable assertion, so a template
 *     holding three sentences must be atomized into three clauses.
 *   - The unwanted-behavior pattern is `IF <trigger>, THEN the <system> SHALL
 *     <response>`; the `THEN` is not optional.
 *   - Every clause needs an explicit actor: `THE SYSTEM` or a named component
 *     such as `THE Chat_Server`. Passive constructions such as "Sensitive
 *     fields SHALL be replaced" name no responsible party and are therefore
 *     untestable.
 *
 * This module is the single gate every generated clause passes through, so an
 * invalid clause cannot reach an output document.
 *
 * Reference: Mavin et al., "Easy Approach to Requirements Syntax (EARS)",
 * RE'09 — the five base patterns plus the complex (multi-precondition) form.
 */

/** Canonical actor. EARS names one responsible entity per requirement. */
const SYSTEM_ACTOR = "THE SYSTEM";

/**
 * Any explicit actor: `THE SYSTEM` or a named component — `THE Chat_Server`,
 * `THE Payment Service`. EARS requires the responsible system to be named, not
 * that it be called "SYSTEM"; specs routinely name the component instead.
 * Accepting only the literal `THE SYSTEM` reported every requirement of such a
 * spec as actorless.
 */
const NAMED_ACTOR = "(?:THE|The|the)\\s+[A-Za-z][\\w-]*(?:\\s+[A-Z][\\w-]*)*";

/** Matches a clause whose obligation has an explicit actor. */
const ACTOR_SHALL = new RegExp(`${NAMED_ACTOR}\\s+SHALL\\b`);

/**
 * Trigger body up to the comma that closes it.
 *
 * Greedy on purpose. A trigger may contain commas of its own — "WHEN the user
 * presses any key other than Enter, PF3, or PF4 on the screen, THE SYSTEM
 * SHALL ..." — so the boundary is the *last* comma before the actor, not the
 * first. A lazy or `[^,]*` match stops inside the list and reports a
 * well-formed requirement as missing its comma.
 */
const TRIGGER_BODY = "(?:[\\s\\S]*,)";

/**
 * Matches what must follow a trigger, with an optional `THEN`: the actor, or
 * a further precondition of a complex requirement (`WHERE <feature>, IF
 * <trigger>, THEN ...`).
 */
const TRIGGER_TERMINATOR = `\\s*(?:THEN\\s+)?(?=${NAMED_ACTOR}\\s+SHALL\\b|WHEN\\b|IF\\b|WHILE\\b|it\\s+SHALL\\b)`;

/**
 * Keywords that open an EARS precondition, mapped to the pattern they select.
 * `IF` is deliberately absent — it is handled separately because it is the only
 * keyword requiring the `THEN` connective.
 */
const TRIGGER_KEYWORDS: ReadonlyArray<{ keyword: string; pattern: EARSPattern }> = [
  { keyword: "WHEN", pattern: "event-driven" },
  { keyword: "WHILE", pattern: "state-driven" },
  { keyword: "WHERE", pattern: "optional-feature" },
];

/**
 * Splits a compound template ahead of each embedded clause opener, without
 * touching sentence-internal periods.
 *
 * A naive split on `. ` would corrupt the many templates containing dotted
 * literals — "TLS 1.2", "169.254.0.0/16", "e.g., Python pickle", "AES-256-GCM".
 * Anchoring the lookahead to the tokens that actually begin an EARS clause keeps
 * those intact while still separating genuine assertion boundaries.
 */
const CLAUSE_BOUNDARY =
  /\.\s+(?=(?:THE SYSTEM\b|IF\b|WHEN\b|WHILE\b|WHERE\b|Sensitive\b|Uploaded\b|All\b))/g;

/**
 * A second `SHALL` joined by a conjunction — "SHALL block that IP AND SHALL
 * alert the monitoring system".
 *
 * This is a compound response: two independently testable obligations in one
 * requirement. Sentence-boundary splitting alone never reaches it, because the
 * two assertions share a sentence. Matched case-insensitively on the conjunction
 * so that both `AND SHALL` and `and SHALL` are caught.
 *
 * Deliberately not global: `split()` does not need the flag, and a `g` regex
 * carries `lastIndex` between `.test()` calls, which would make validation
 * return a false negative on every second call.
 */
const SHALL_CONJUNCTION = /\s+(?:AND|and)\s+(?=SHALL\b)/;

/** Verbs and copulas that must never terminate an extracted actor phrase. */
const VERB_TOKENS = new Set([
  "submits", "submit", "requests", "request", "performs", "perform",
  "enters", "enter", "provides", "provide", "supplies", "supply",
  "presses", "press", "creates", "create", "processes", "process",
  "writes", "write", "reads", "read", "updates", "update", "deletes", "delete",
  "displays", "display", "returns", "return", "sends", "send",
  "uploads", "upload", "fetches", "fetch", "confirms", "confirm",
  "selects", "select", "validates", "validate", "retrieves", "retrieve",
  "is", "are", "was", "were", "be", "been", "being",
  "has", "have", "had", "does", "do", "did",
  "shall", "will", "must", "may", "can", "should", "would",
  "occurs", "occur", "fails", "fail", "succeeds", "succeed",
  "exceeds", "exceed", "reaches", "reach", "detected", "found", "received",
]);

/**
 * Nouns that cannot act — a trigger clause needs an agent capable of performing
 * the verb, and "WHEN duplicate key submits the input" is not a testable trigger.
 */
const NON_AGENT_TOKENS = new Set([
  "error", "errors", "key", "balance", "amount", "field", "fields",
  "end", "start", "write", "read", "browse", "card", "account",
  "transaction", "record", "data", "file", "screen", "message",
  "value", "values", "date", "time", "count", "status", "state",
  "condition", "result", "response", "payment", "update", "lookup",
]);

/**
 * Function words that cannot end an agent noun phrase. A capture terminating on
 * one ("end of", "card for") ran short of, or past, the actual noun.
 */
const TRAILING_STOP_WORDS = new Set([
  "of", "for", "to", "in", "on", "at", "by", "with", "from",
  "the", "a", "an", "and", "or", "but", "as",
]);

/**
 * Active present-tense verbs that cannot legitimately follow another verb inside
 * a trigger. Their appearance after a verb marks a mangled actor capture. The
 * set deliberately excludes past participles (received, detected, rendered),
 * which form valid passive-event triggers such as "WHEN input is received".
 */
const ACTIVE_TRIGGER_VERBS = new Set([
  "submits", "submit", "requests", "request", "presses", "press",
  "enters", "enter", "provides", "provide", "supplies", "supply",
  "creates", "create", "processes", "process", "confirms", "confirm",
  "selects", "select", "uploads", "upload", "views", "view",
]);

/**
 * A trailing temporal qualifier inside a response clause — "... matches the
 * resource owner before executing the operation."
 *
 * EARS puts temporal conditions in the precondition, not the response: a `SHALL`
 * body states *what* the system does, and a `WHEN`/`WHILE` clause states *when*.
 * A response carrying its own "before ..." is therefore a hidden trigger, and
 * hiding it makes the requirement untestable — there is no named point in time
 * at which to check the obligation.
 *
 * The captured group is the event, which `hoistEmbeddedPrecondition` promotes to
 * a leading `WHILE`/`WHEN` clause. `prior to` is included as its common variant.
 */
const EMBEDDED_PRECONDITION =
  /,?\s+(?:before|prior to)\s+((?:any\s+|the\s+|all\s+)?[a-z][^,.]*?)\s*(?=[.]|$)/i;

/**
 * Gerund-phrase events that read naturally under `WHILE` rather than `WHEN`.
 *
 * "before executing the operation" describes an interval the obligation must
 * hold across, which is EARS state-driven (`WHILE`). "before the token expires"
 * names a discrete moment, which is event-driven (`WHEN`). Choosing the wrong
 * keyword changes the requirement's meaning, so the distinction is explicit
 * rather than defaulted.
 */
const GERUND_EVENT = /^(?:any\s+|the\s+|all\s+)?\w+ing\b/i;

/**
 * An event phrased as a clause with its own subject and verb: "the token
 * expires", "the session is renewed", "a record has been written".
 */
const CLAUSE_EVENT =
  /^(?:the|a|an|any|each|all|every)\s+(?:\S+\s+)*?(?:(?:is|are|was|were|has|have|had)\b|\w+(?:s|ed)$)/i;

/**
 * True when a "before <event>" qualifier names an event that can become a
 * leading trigger. A gerund phrase becomes `WHILE <object> is being <done>`, and
 * a subject-and-verb clause becomes `WHEN <clause>`. A bare noun — "before use",
 * "before deployment", "before the deadline" — names no event, so moving it
 * produces a trigger such as `WHEN use,` that states nothing testable. Such a
 * qualifier stays where it is, in the response.
 */
export function isHoistableEvent(event: string): boolean {
  const text = event.trim();
  return GERUND_EVENT.test(text) || CLAUSE_EVENT.test(text);
}

export interface EARSValidationResult {
  valid: boolean;
  pattern?: EARSPattern;
  errors: string[];
}

/**
 * Rewrites a trailing "before <event>" qualifier into a leading EARS trigger.
 *
 * `THE SYSTEM SHALL verify ownership before executing the operation.`
 *   becomes
 * `WHILE the operation is being executed, THE SYSTEM SHALL verify ownership.`
 *
 * A clause that already carries a precondition is returned unchanged: stacking a
 * second trigger onto it would silently narrow the requirement's scope, which is
 * a semantic change rather than the formatting repair intended here.
 */
export function hoistEmbeddedPrecondition(clause: string): string {
  const text = clause.trim();
  if (hasTriggerPrefix(text)) return text;

  const match = text.match(EMBEDDED_PRECONDITION);
  if (!match) return text;

  const event = match[1].trim();
  if (!isHoistableEvent(event)) return text;
  const body = text.slice(0, match.index).trim().replace(/,$/, "");
  if (!body) return text;

  // The response must survive the move intact — a capture that swallowed the
  // actor would leave a fragment with no SHALL behind.
  if (!/\bSHALL\b/.test(body)) return text;

  const trigger = GERUND_EVENT.test(event)
    ? `WHILE ${toPassiveInterval(event)},`
    : `WHEN ${event},`;

  return ensureTerminalPeriod(`${trigger} ${body}`);
}

/**
 * Turns a gerund event phrase into the passive state clause a `WHILE` trigger
 * needs: "executing the operation" -> "the operation is being executed".
 *
 * Falls back to a bare "<phrase> is in progress" when the phrase has no object
 * to promote ("before deployment"), which stays grammatical without inventing a
 * subject the source did not name.
 */
function toPassiveInterval(event: string): string {
  const match = event.match(/^(?:any\s+|the\s+|all\s+)?(\w+)ing\s+(.+)$/i);
  if (!match) return `${event} is in progress`;

  const [, stem, object] = match;
  const participle = toPastParticiple(stem);
  const hasArticle = /^(?:the|a|an|any|all)\b/i.test(object);

  return `${hasArticle ? object : `the ${object}`} is being ${participle}`;
}

/** Irregular participles appearing in the constraint templates. */
const IRREGULAR_PARTICIPLES: Record<string, string> = {
  writ: "written",
  process: "processed",
  render: "rendered",
  execut: "executed",
  us: "used",
  allow: "allowed",
  deploy: "deployed",
};

function toPastParticiple(stem: string): string {
  const known = IRREGULAR_PARTICIPLES[stem.toLowerCase()];
  if (known) return known;

  // Gerund stems drop a silent `e` ("execute" -> "execut"), so a consonant-final
  // stem needs it restored before `-d`.
  return /[aeiou]$/.test(stem) ? `${stem}d` : `${stem}ed`;
}

/**
 * Decides whether an extracted phrase may be substituted into an `{actor}` slot.
 *
 * Templates read `WHEN {actor} submits ...`, so the slot must hold a bare agent
 * noun phrase. Admitting a phrase whose head is a verb is what produced the
 * "WHEN user submits submits the input" defect; admitting a non-agent noun is
 * what produced "WHEN duplicate key submits the input".
 */
export function isValidActorPhrase(phrase: string): boolean {
  const trimmed = phrase.trim().toLowerCase();
  if (!trimmed) return false;

  const words = trimmed.split(/\s+/);
  if (words.length > 3) return false;

  // A verb anywhere in the phrase means the regex ran past the noun phrase.
  if (words.some((word) => VERB_TOKENS.has(word))) return false;

  const head = words[words.length - 1];
  if (NON_AGENT_TOKENS.has(head)) return false;

  // A phrase ending in a function word ("end of", "top for") is a truncated
  // capture, not an agent.
  if (TRAILING_STOP_WORDS.has(head)) return false;

  return words.every((word) => /^[a-z][a-z-]*$/.test(word));
}

/**
 * Splits a template into atomic clauses, propagating the precondition.
 *
 * When a triggered template is atomized, later sentences inherit the leading
 * trigger. Dropping it would silently widen each follow-on assertion from
 * "only under this condition" to "at all times".
 */
export function atomizeTemplate(template: string): string[] {
  const sentences = template
    .split(CLAUSE_BOUNDARY)
    .map((segment) => segment.trim())
    .filter(Boolean);

  const trigger = extractTriggerPrefix(sentences[0] ?? "");

  // Each sentence may itself hold a conjoined second obligation, so split on
  // `AND SHALL` after the sentence split rather than instead of it.
  const segments = sentences.flatMap((sentence) =>
    splitShallConjunction(sentence)
  );

  if (segments.length <= 1) {
    return [ensureTerminalPeriod(hoistEmbeddedPrecondition(template.trim()))];
  }

  return segments.map((segment, index) => {
    const clause =
      index === 0 || !trigger || hasTriggerPrefix(segment)
        ? segment
        : `${trigger} ${segment}`;
    return ensureTerminalPeriod(hoistEmbeddedPrecondition(clause.trim()));
  });
}

/**
 * Splits a sentence at `AND SHALL`, re-attaching the actor to each continuation.
 *
 * "THE SYSTEM SHALL block that IP AND SHALL alert the monitor" yields two
 * clauses, the second of which needs `THE SYSTEM` restored — a bare
 * "SHALL alert the monitor" names no responsible party and would be rejected by
 * `validateEARSClause` as actorless.
 *
 * Only `AND` is split. `or` joins alternative ways of satisfying one obligation
 * ("bcrypt, scrypt, or Argon2id"), which is a single assertion and must stay
 * whole; splitting it would turn a choice into two mandates.
 */
function splitShallConjunction(sentence: string): string[] {
  const parts = sentence
    .split(SHALL_CONJUNCTION)
    .map((part) => part.trim())
    .filter(Boolean);

  if (parts.length <= 1) return [sentence.trim()];

  const trigger = extractTriggerPrefix(parts[0]);

  return parts.map((part, index) => {
    if (index === 0) return part;

    // Carry the precondition and the actor onto the continuation clause.
    const withActor = /^SHALL\b/.test(part) ? `${SYSTEM_ACTOR} ${part}` : part;
    return trigger && !hasTriggerPrefix(withActor)
      ? `${trigger} ${withActor}`
      : withActor;
  });
}

/**
 * Returns the `WHEN ...,` / `IF ..., THEN` prefix of a clause, or undefined when
 * the clause is ubiquitous.
 */
function extractTriggerPrefix(clause: string): string | undefined {
  // `THEN` is optional here on purpose: atomization runs before normalization,
  // so a template's `IF ..., THE SYSTEM SHALL` has not yet gained its `THEN`.
  // Requiring it would return undefined and drop the precondition from every
  // continuation clause — silently widening a conditional security constraint
  // into an unconditional one.
  const ifMatch = clause.match(
    new RegExp(`^(IF\\b${TRIGGER_BODY})${TRIGGER_TERMINATOR}`, "i")
  );
  if (ifMatch) return `${ifMatch[1]} THEN`;

  for (const { keyword } of TRIGGER_KEYWORDS) {
    const match = clause.match(
      new RegExp(`^(${keyword}\\b${TRIGGER_BODY})${TRIGGER_TERMINATOR}`, "i")
    );
    if (match) return match[1];
  }

  return undefined;
}

function hasTriggerPrefix(clause: string): boolean {
  return /^(?:IF|WHEN|WHILE|WHERE)\b/i.test(clause.trim());
}

function ensureTerminalPeriod(clause: string): string {
  return /[.!?]$/.test(clause) ? clause : `${clause}.`;
}

/**
 * Replaces a bare `it SHALL` response actor with `THE SYSTEM SHALL`.
 *
 * Substitutes only when the subject of the *nearest* trigger clause is the system
 * — "WHEN the system processes the payment, it SHALL ..." — which fixes the
 * referent beyond doubt. Testing the trigger's subject rather than its last noun
 * matters: that trigger's last noun is "the payment", so a nearest-noun rule
 * would refuse a requirement whose referent is in fact unambiguous.
 *
 * Where the subject is anything else — "WHEN the batch job completes, it SHALL
 * ..." — the pronoun plausibly points at that noun, and guessing would rewrite
 * the requirement's subject. Those are left for `validateEARSClause` to report so
 * a human resolves them.
 */
function resolveSystemPronoun(clause: string): string {
  const match = clause.match(/^(.*?,\s*(?:THEN\s+)?)it(?=\s+SHALL\b)/i);
  if (!match) return clause;

  const trigger = match[1];
  const subjects = [
    ...trigger.matchAll(/\b(?:IF|WHEN|WHILE|WHERE)\b\s+(?:the\s+)?([a-z][\w-]*)/gi),
  ];
  const nearest = subjects[subjects.length - 1]?.[1];
  if (!nearest || !/^system$/i.test(nearest)) return clause;

  return `${trigger}${SYSTEM_ACTOR}${clause.slice(trigger.length + "it".length)}`;
}

/**
 * Repairs the mechanical grammar deviations a template can carry: a missing
 * `THEN` after an `IF` precondition, a lowercase actor, and doubled whitespace.
 *
 * Semantic defects — an unfilled placeholder, a passive clause, an unusable
 * trigger — are not repairable here and are surfaced by `validateEARSClause`
 * instead of being papered over.
 */
export function normalizeEARSClause(clause: string): string {
  let result = clause.trim().replace(/\s+/g, " ");

  // Canonical uppercase keywords. EARS keywords are structural markers, not
  // prose, so a lowercase "When" is a formatting defect rather than a style
  // choice — parsers keyed on the keyword must not depend on casing.
  result = result.replace(/^(if|when|while|where)\b/i, (kw) => kw.toUpperCase());

  // A complex clause stacks two triggers ("WHILE <state>, when <trigger>, ..."),
  // so uppercasing only the leading keyword leaves the second one lowercase.
  // Rewriting is confined to the text before the response's SHALL: these words
  // occur as ordinary prose inside a response body ("... log the time, when
  // available, to the audit trail"), where they are not EARS keywords.
  const shallAt = result.search(/\b(?:SHALL|shall)\b/);
  if (shallAt > 0) {
    result =
      result
        .slice(0, shallAt)
        .replace(/,\s*(if|when|while|where)\b/gi, (_, kw) => `, ${kw.toUpperCase()}`) +
      result.slice(shallAt);
  }

  result = result.replace(/,\s*then\b/i, ", THEN");
  result = result.replace(/\bthe system shall not\b/gi, `${SYSTEM_ACTOR} SHALL NOT`);
  result = result.replace(/\bthe system shall\b/gi, `${SYSTEM_ACTOR} SHALL`);
  result = result.replace(/\bshall\b/g, "SHALL");
  result = resolveSystemPronoun(result);

  // `IF <trigger>, THE SYSTEM SHALL` -> `IF <trigger>, THEN THE SYSTEM SHALL`
  result = result.replace(
    new RegExp(`^(IF\\b${TRIGGER_BODY})\\s*(?!THEN\\b)(${SYSTEM_ACTOR}\\b)`, "i"),
    `$1 THEN $2`
  );

  // A trailing "before <event>" is a trigger in the wrong position; move it.
  result = hoistEmbeddedPrecondition(result);

  return ensureTerminalPeriod(result);
}

/**
 * Classifies a clause by its EARS pattern using the precondition keywords alone.
 *
 * `SHALL NOT` is a negative *response*, not a pattern — a common misreading that
 * conflates it with the unwanted-behavior form. Only `IF ..., THEN` is
 * unwanted-behavior.
 */
export function classifyEARSPattern(clause: string): EARSPattern | undefined {
  const text = clause.trim();

  // Two different stacked preconditions (WHILE <state>, WHEN <trigger>; WHERE
  // <feature>, IF <trigger>) => complex. Only the text ahead of the response's
  // SHALL is a precondition; the same words inside a response are prose.
  const shallAt = text.search(/\bSHALL\b/i);
  const preconditions = shallAt >= 0 ? text.slice(0, shallAt) : text;
  const keywords = new Set(
    [...preconditions.matchAll(/(?:^|,\s*)(IF|WHEN|WHILE|WHERE)\b/gi)].map((m) =>
      m[1].toUpperCase()
    )
  );
  if (keywords.size >= 2) return "complex";

  const hasWhile = /^WHILE\b/i.test(text);
  const hasIf = /^IF\b/i.test(text);

  if (hasIf) return "unwanted-behavior";
  if (/^WHEN\b/i.test(text)) return "event-driven";
  if (hasWhile) return "state-driven";
  if (/^WHERE\b/i.test(text)) return "optional-feature";
  if (/\bSHALL\b/.test(text)) return "ubiquitous";

  return undefined;
}

/**
 * Validates a clause against the strict EARS grammar. Every generated clause is
 * checked before it is written, so violations fail loudly at generation time
 * rather than surfacing as unparseable text in a delivered spec.
 */
export function validateEARSClause(clause: string): EARSValidationResult {
  const errors: string[] = [];
  const text = clause.trim();

  if (!text) {
    return { valid: false, errors: ["clause is empty"] };
  }

  if (!/\bSHALL\b/.test(text)) {
    errors.push("clause contains no SHALL — not a requirement");
  }

  if (/\{[a-z_]+\}/i.test(text)) {
    errors.push(`unsubstituted placeholder: ${text.match(/\{[a-z_]+\}/i)?.[0]}`);
  }

  // Atomicity: a second clause opener after a sentence break means two assertions.
  if (new RegExp(`\\.\\s+(?:${NAMED_ACTOR}\\s+SHALL|IF|WHEN|WHILE|WHERE)\\b`).test(text)) {
    errors.push("clause is compound — contains more than one assertion");
  }

  // Atomicity: a second SHALL joined by AND is likewise two obligations.
  if (SHALL_CONJUNCTION.test(text)) {
    errors.push(
      "clause is compound — 'AND SHALL' joins two obligations in one requirement"
    );
  }

  // A response may not carry its own temporal condition when that condition is
  // an event; it belongs in a WHEN/WHILE precondition, where it is testable. A
  // bare-noun qualifier ("before use") is part of the response, not an event.
  const embedded = text.match(EMBEDDED_PRECONDITION);
  if (embedded && isHoistableEvent(embedded[1])) {
    errors.push(
      "response contains an embedded precondition — move 'before ...' into a WHEN/WHILE clause"
    );
  }

  // Every SHALL must be governed by an explicit actor or an AND continuation.
  if (!ACTOR_SHALL.test(text) && /\bSHALL\b/.test(text)) {
    errors.push(
      "clause has no explicit actor — 'THE <system or component> SHALL' is required"
    );
  }

  // Passive assertion: a SHALL whose subject is not a named actor.
  const passive = text.match(/(?:^|\.\s+)(?!THE\s)([A-Z][\w\s]*?)\s+SHALL\s+be\b/);
  if (passive) {
    errors.push(`passive assertion with no responsible actor: "${passive[1].trim()}"`);
  }

  if (
    /^IF\b/i.test(text) &&
    !new RegExp(`^IF\\b${TRIGGER_BODY}\\s*THEN\\b`, "i").test(text)
  ) {
    errors.push("unwanted-behavior pattern requires 'IF <trigger>, THEN ...'");
  }

  for (const { keyword } of TRIGGER_KEYWORDS) {
    if (new RegExp(`^${keyword}\\b`, "i").test(text)) {
      if (
        !new RegExp(`^${keyword}\\b${TRIGGER_BODY}${TRIGGER_TERMINATOR}`, "i").test(text)
      ) {
        errors.push(
          `${keyword} precondition must be closed by a comma before the actor`
        );
      }
    }
  }

  // A finite active verb following another verb signals a trigger assembled from
  // a bad actor extraction ("user submits submits", "account is submits"). A
  // copula followed by a participle ("input is received", "content is rendered")
  // is valid passive-event phrasing and must not be flagged.
  const triggerBody = text.match(
    new RegExp(`^(?:IF|WHEN|WHILE|WHERE)\\b\\s+(${TRIGGER_BODY})${TRIGGER_TERMINATOR}`, "i")
  )?.[1];
  if (triggerBody) {
    const raw = triggerBody.split(/\s+/);
    const words = raw.map((word) => word.toLowerCase());
    for (let i = 0; i < words.length - 1; i++) {
      // A capitalized second token is a proper noun, not a verb — "presses Enter"
      // and "presses PF4" name keys. Lowercasing before the test would read them
      // as a doubled verb and reject a well-formed trigger.
      if (/^[A-Z]/.test(raw[i + 1])) continue;

      if (VERB_TOKENS.has(words[i]) && ACTIVE_TRIGGER_VERBS.has(words[i + 1])) {
        errors.push(
          `malformed trigger — adjacent verbs "${words[i]} ${words[i + 1]}"`
        );
        break;
      }
    }
    if (/\b(\w+)\s+\1\b/i.test(triggerBody)) {
      errors.push("malformed trigger — duplicated word");
    }
    // A one-word trigger ("WHEN use,", "WHEN deployment,") names no event or
    // state, so there is no point in time at which to test the obligation.
    const lastTrigger = triggerBody.replace(/,\s*$/, "").split(/,\s*(?:WHEN|WHILE|WHERE|IF)\b/i).pop() ?? "";
    if (lastTrigger.trim().split(/\s+/).filter(Boolean).length < 2) {
      errors.push(`malformed trigger — "${lastTrigger.trim()}" names no event or state`);
    }
  }

  const pattern = classifyEARSPattern(text);
  if (!pattern) {
    errors.push("clause matches no EARS pattern");
  }

  return { valid: errors.length === 0, pattern, errors };
}

/**
 * Full pipeline for one template: atomize, normalize, validate.
 *
 * Invalid clauses are returned separately rather than dropped silently, so the
 * caller can surface them; a spec that quietly loses a security constraint is
 * more dangerous than one that reports a generation failure.
 */
export function toValidEARSClauses(template: string): {
  clauses: string[];
  rejected: Array<{ clause: string; errors: string[] }>;
} {
  const clauses: string[] = [];
  const rejected: Array<{ clause: string; errors: string[] }> = [];

  for (const atom of atomizeTemplate(template)) {
    const normalized = normalizeEARSClause(atom);
    const validation = validateEARSClause(normalized);

    if (validation.valid) {
      clauses.push(normalized);
    } else {
      rejected.push({ clause: normalized, errors: validation.errors });
    }
  }

  return { clauses, rejected };
}
