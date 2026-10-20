import { isValidActorPhrase } from "./ears-normalizer.js";
/**
 * Turns a constraint template into the text proposed for one requirement.
 *
 * Three steps, shared by every place a template is shown — proposals, the
 * semantic-review list and the template tests — so they cannot drift apart:
 *
 *   1. `resolveTemplate` picks the wording that fits the spec: a context
 *      variant ("web-accessible document root" only for a web spec) and
 *      language-specific examples ("Go encoding/gob" for a Go spec instead of
 *      Java and Python).
 *   2. `fillTemplate` fills `{placeholder}` slots from the requirement.
 *   3. Slots it cannot fill fall back to generic text, and are reported, so a
 *      clause such as "WHEN a user requests a privilege escalation for the
 *      target" is flagged as a draft rather than passing as finished.
 */
/** Generic text for each slot, used when the requirement does not supply it. */
const GENERIC_FALLBACKS = {
    actor: "a user",
    // `{operation}` holds a verb phrase ("assign the room") and is always written
    // after "to", so its fallback is a verb phrase too.
    operation: "perform the operation",
    resource: "the resource",
    input_description: "the input",
    target_state: "the target state",
    target: "the target",
    required_role: "required",
    high_value_operation: "the operation",
    configured_limit: "the configured limit",
};
/**
 * Slots whose generic fallback still reads as a complete requirement. "a user"
 * names the usual actor; every other fallback ("the target", "the operation")
 * leaves the reader asking which one.
 */
const ACCEPTABLE_FALLBACKS = new Set(["actor"]);
/** Verbs that disqualify a phrase from an `{input_description}` slot. */
const VERB_TOKENS_FOR_INPUT = new Set([
    "submits", "submit", "presses", "press", "enters", "enter",
    "requests", "request", "is", "are", "was", "were", "shall", "will",
    "occurs", "occur", "fails", "fail", "detected", "received",
]);
/**
 * Language-specific examples for a concept, cited by an `{<concept>_examples}`
 * slot. Each entry names the API in that language that exhibits the weakness.
 */
const LANGUAGE_EXAMPLES = {
    deserialization: {
        go: "Go encoding/gob decoding into interface-typed fields",
        java: "Java ObjectInputStream",
        python: "Python pickle",
        javascript: "Node.js node-serialize or eval-based parsers",
        dotnet: ".NET BinaryFormatter",
        ruby: "Ruby Marshal.load",
        php: "PHP unserialize",
    },
};
/** Languages cited when a spec names none: the most widely affected ones. */
const DEFAULT_EXAMPLE_LANGUAGES = ["java", "python", "dotnet"];
/**
 * The wording of a constraint for a spec: the first variant whose feature the
 * spec has, else the default template, with example slots resolved.
 */
export function resolveTemplate(constraint, context) {
    const variant = context
        ? constraint.variants?.find((v) => context.features.includes(v.when))
        : undefined;
    const template = variant?.template ?? constraint.template;
    return template.replace(/\{(\w+)_examples\}/g, (slot, concept) => {
        const table = LANGUAGE_EXAMPLES[concept];
        if (!table)
            return slot;
        const named = (context?.languages ?? []).filter((language) => table[language]);
        const languages = named.length > 0 ? named : DEFAULT_EXAMPLE_LANGUAGES;
        return `e.g., ${languages.map((language) => table[language]).join(", ")}`;
    });
}
/**
 * Fills a template's `{placeholder}` slots from the requirement text.
 *
 * Extraction is conservative: a slot is filled only when the candidate phrase
 * is verified to fit that position. A doubtful extraction is declined in favour
 * of the generic fallback, which is always grammatical, and the fallback is
 * reported in `genericSlots`.
 */
export function fillTemplate(template, requirementText = "") {
    const extracted = {
        actor: extractActor(requirementText),
        operation: extractOperation(requirementText),
        resource: requirementText
            .match(/(?:the|a|an)\s+(\w+(?:\s+\w+)?)\s+(?:resource|record|data|entity|object)/i)?.[1]
            ?.toLowerCase(),
        input_description: extractInputDescription(requirementText),
    };
    const genericSlots = [];
    const text = template.replace(/\{(\w+)\}/g, (placeholder, slot) => {
        const value = extracted[slot];
        if (value)
            return value;
        const fallback = GENERIC_FALLBACKS[slot];
        if (fallback === undefined)
            return placeholder;
        if (!ACCEPTABLE_FALLBACKS.has(slot) && !genericSlots.some((g) => g.slot === slot)) {
            genericSlots.push({ slot, filledWith: fallback });
        }
        return fallback;
    });
    return { text, genericSlots };
}
/**
 * Pulls the agent noun phrase out of a requirement's trigger clause, for
 * templates reading `WHEN {actor} submits ...`. Third-person verbs only:
 * "IF a registration request contains ..." would otherwise read
 * "registration" as an actor performing "request".
 */
function extractActor(text) {
    const patterns = [
        /\b(?:when|while|if)\s+(?:a|an|the)\s+([a-z]+(?:\s+[a-z]+)?)\s+(?:submits|requests|presses|enters|provides|selects|uploads|confirms|attempts|performs|initiates|views)\b/i,
        /\bthe\s+([a-z]+(?:\s+[a-z]+)?)\s+(?:submits|requests|presses|enters|provides|selects|uploads|confirms)\b/i,
    ];
    for (const pattern of patterns) {
        const candidate = text.match(pattern)?.[1];
        if (candidate && isValidActorPhrase(candidate)) {
            const normalized = candidate.trim().toLowerCase();
            if (/^(?:a|an|the)\s/.test(normalized))
                return normalized;
            // "an administrator", but "a user": a leading "u" that sounds like "you".
            return /^(?:[aeio]|u(?!s|ni|ti))/.test(normalized) ? `an ${normalized}` : `a ${normalized}`;
        }
    }
    return undefined;
}
/**
 * Extracts the verb phrase following `shall` for `{operation}` slots. Only a
 * verb-initial phrase is accepted; auxiliaries and negation carry none.
 */
function extractOperation(text) {
    const match = text.match(/\bshall\s+([a-z]+(?:\s+[a-z]+){0,2})/i);
    if (!match)
        return undefined;
    const phrase = match[1].trim().toLowerCase();
    const head = phrase.split(/\s+/)[0];
    if (["not", "be", "been", "have", "has", "also", "then"].includes(head)) {
        return undefined;
    }
    return phrase;
}
/**
 * Extracts the object of a submission verb for `{input_description}`, which
 * sits in "submits {input_description}" and so must be a noun phrase.
 */
function extractInputDescription(text) {
    const match = text.match(/\b(?:submits?|provides?|enters?|supplies?)\s+((?:a|an|the)\s+[\w\s]+?)(?:,|\.|$)/i);
    if (!match)
        return undefined;
    const phrase = match[1].trim().toLowerCase().replace(/\s+/g, " ");
    if (phrase.split(/\s+/).length > 6)
        return undefined;
    const body = phrase.replace(/^(?:a|an|the)\s+/, "");
    if (body.split(/\s+/).some((word) => VERB_TOKENS_FOR_INPUT.has(word))) {
        return undefined;
    }
    return phrase;
}
//# sourceMappingURL=template-filler.js.map