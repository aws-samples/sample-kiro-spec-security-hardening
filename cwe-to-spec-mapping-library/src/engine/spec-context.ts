import type {
  CWEMapping,
  EARSConstraint,
  SpecContext,
  SpecFeature,
  SpecLanguage,
} from "../types/index.js";

/**
 * Document-level context: which technologies a spec uses and what it declares
 * out of scope.
 *
 * Trigger detection reads one requirement at a time, so on its own it cannot
 * tell that a chat server has no database, renders no HTML, or that its authors
 * decided TLS is out of scope. Without that context it proposes parameterized
 * SQL for a "search" requirement and TLS for a latency requirement — constraints
 * that either target a component the system does not have or contradict a
 * decision the spec records. Reading the whole document once settles both.
 */

/** Evidence, anywhere in the document, that a spec uses a feature. */
const FEATURE_EVIDENCE: Record<SpecFeature, RegExp> = {
  "sql-database":
    /\b(?:sql|databases?|rdbms|postgres(?:ql)?|mysql|sqlite|mariadb|mssql|oracle db|dynamodb|mongodb|cassandra|orm|stored procedures?)\b/i,
  // Pages, forms and buttons mean a browser UI: "submits a registration form",
  // "redirect to the login page".
  http: /\b(?:https?|rest(?:ful)?|endpoints?|web|websites?|web ?servers?|web app(?:lication)?s?|web services?|cookies?|browsers?|urls?|graphql|webhooks?|api gateway|pages?|forms?|buttons?|redirects?)\b/i,
  html: /\b(?:html|browsers?|web|websites?|web ?pages?|pages?|dom|javascript|front-?end|web ui|single-page)\b/i,
  xml: /\b(?:xml|xpath|xslt|soap|svg|dtd)\b/i,
  ldap: /\b(?:ldap|active directory)\b/i,
};

/**
 * Evidence that a spec is implemented in a language. Deliberately specific:
 * "go" is an ordinary English verb, so Go is recognized only from phrasing
 * such as "written in Go", "Go 1.22", "Go module", "golang" or "goroutine".
 */
const LANGUAGE_EVIDENCE: Record<SpecLanguage, RegExp> = {
  go: /\b(?:[Gg]olang|[Gg]oroutines?|go\.mod)\b|\b[Gg]o\s+(?:1\.\d+|modules?|programs?|standard library|channels?|toolchain|race detector)\b|\b(?:in|using|with) Go\b|\bGo's\b/,
  java: /\b(?:java(?!script)|jvm|spring boot|kotlin)\b/i,
  python: /\b(?:python|django|flask|fastapi)\b/i,
  javascript: /\b(?:javascript|typescript|node\.?js|npm|deno)\b/i,
  dotnet: /(?:^|[^\w])(?:c#|\.net|asp\.net|dotnet)(?![\w])/i,
  ruby: /\b(?:ruby|rails)\b/i,
  php: /\b(?:php|laravel)\b/i,
};

/** Phrases that declare something out of scope. */
const OUT_OF_SCOPE = /\b(?:out[- ]of[- ]scope|not in scope|non-goals?)\b/i;

/** A heading that opens an out-of-scope section ("## Out of Scope", "### Non-Goals"). */
const OUT_OF_SCOPE_HEADING = /^#{1,6}\s+.*\b(?:out[- ]of[- ]scope|non-goals?)\b/i;

/**
 * Reads a spec document once and returns its context.
 *
 * Out-of-scope statements are collected at sentence level, so a long
 * introductory paragraph that mentions one out-of-scope item does not put
 * everything else in that paragraph out of scope too. Every list item under an
 * "Out of Scope" heading is collected whole.
 */
export function detectSpecContext(content: string): SpecContext {
  const features = (Object.keys(FEATURE_EVIDENCE) as SpecFeature[]).filter(
    (feature) => FEATURE_EVIDENCE[feature].test(content)
  );

  const languages = (Object.keys(LANGUAGE_EVIDENCE) as SpecLanguage[]).filter(
    (language) => LANGUAGE_EVIDENCE[language].test(content)
  );

  const outOfScope: string[] = [];
  let inSection = false;

  for (const line of content.split("\n")) {
    if (/^#{1,6}\s/.test(line)) {
      inSection = OUT_OF_SCOPE_HEADING.test(line);
      continue;
    }
    if (inSection && line.trim()) {
      outOfScope.push(line.trim().toLowerCase());
      continue;
    }
    if (!OUT_OF_SCOPE.test(line)) continue;
    for (const sentence of line.split(/(?<=[.;!?])\s+/)) {
      if (OUT_OF_SCOPE.test(sentence)) outOfScope.push(sentence.trim().toLowerCase());
    }
  }

  return { features, outOfScope, languages };
}

/**
 * Why a constraint must not be proposed for this spec, or undefined when it
 * applies. Checked for the mapping first, then for the constraint itself.
 */
export function contextSuppressionReason(
  mapping: CWEMapping,
  constraint: EARSConstraint,
  context: SpecContext
): string | undefined {
  for (const required of [mapping.requiresContext, constraint.requiresContext]) {
    if (required && !required.some((feature) => context.features.includes(feature))) {
      return `spec shows no ${required.join(" or ")} component`;
    }
  }

  for (const term of constraint.outOfScopeTerms ?? []) {
    const pattern = new RegExp(`\\b${term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`, "i");
    if (context.outOfScope.some((statement) => pattern.test(statement))) {
      return `spec declares "${term}" out of scope`;
    }
  }

  return undefined;
}
