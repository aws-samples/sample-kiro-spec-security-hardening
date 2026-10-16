import type { Requirement, TriggeredCWE, CWEMapping } from "../types/index.js";
import { allMappings } from "../mappings/index.js";

export class CoverageChecker {
  private mappings: CWEMapping[];

  constructor(mappings: CWEMapping[] = allMappings) {
    this.mappings = mappings;
  }

  checkCoverage(
    requirements: Requirement[],
    triggeredCWEs: TriggeredCWE[]
  ): CoverageGap[] {
    const gaps: CoverageGap[] = [];
    const allText = requirements.map((r) => r.text.toLowerCase()).join(" ");
    const allAnnotations = requirements
      .flatMap((r) => r.securityAnnotations ?? [])
      .map((a) => a.toLowerCase());

    for (const triggered of triggeredCWEs) {
      const mapping = this.mappings.find((m) => m.id === triggered.cweId);
      if (!mapping) continue;

      for (const constraint of mapping.earsConstraints) {
        const isCovered = this.isConstraintCovered(
          allText,
          allAnnotations,
          constraint.securityPrimitive,
          constraint.template
        );

        if (!isCovered) {
          gaps.push({
            cweId: triggered.cweId,
            cweName: triggered.cweName,
            severity: triggered.severity,
            missingPrimitive: constraint.securityPrimitive,
            constraintId: constraint.id,
            suggestedTemplate: constraint.template,
            rationale: constraint.rationale,
          });
        }
      }
    }

    return gaps;
  }

  private isConstraintCovered(
    fullText: string,
    annotations: string[],
    primitive: string,
    template: string
  ): boolean {
    if (annotations.includes(primitive.toLowerCase())) {
      return true;
    }

    const coverageIndicators = this.extractCoverageIndicators(primitive, template);
    const matchCount = coverageIndicators.filter((indicator) =>
      fullText.includes(indicator.toLowerCase())
    ).length;

    return matchCount >= Math.ceil(coverageIndicators.length * 0.6);
  }

  private extractCoverageIndicators(primitive: string, template: string): string[] {
    const indicatorMap: Record<string, string[]> = {
      "parameterized-query": ["parameterized", "prepared statement", "shall not construct query strings by concatenation"],
      "input-validation": ["sanitize", "allowlist", "validate", "allowlisted character set"],
      "output-encoding": ["encode", "output encoding", "content security policy"],
      "html-sanitization": ["sanitize", "sanitization library", "strip"],
      "authentication-required": ["authenticated session", "signed token", "require.*authentication"],
      "authentication-enforcement": ["401", "unauthenticated", "no valid authentication"],
      "rate-limiting": ["rate limit", "back-off", "maximum.*attempts", "throttle"],
      "ip-rate-limiting": ["block.*ip", "per ip", "ip.*limit"],
      "constant-time-comparison": ["constant time", "dummy hash"],
      "password-hashing": ["bcrypt", "hash.*password", "cost factor"],
      "strong-password-hash": ["bcrypt", "scrypt", "argon2"],
      "session-expiration": ["session.*duration", "invalidate.*session", "expire"],
      "session-regeneration": ["new session", "invalidate.*pre-existing", "regenerat"],
      "ownership-verification": ["verify.*owner", "matches.*owner", "permission grant", "ownership"],
      "authorization-denial": ["403", "no data payload", "forbidden"],
      "role-verification": ["verify.*role", "holds.*role", "role assignment"],
      "idor-prevention": ["verify.*tenant", "owning tenant", "matches.*authenticated"],
      "csrf-protection": ["csrf token", "validate.*token.*on.*state-mutating"],
      "privilege-escalation-control": ["super-set", "audit.*privilege"],
      "tenant-isolation": ["tenant_id", "tenant isolation", "mandatory filter"],
      "data-minimization": ["minimum fields", "shall not expose"],
      "outbound-data-allowlist": ["allowlist.*non-credential", "explicit allowlist"],
      "credential-exclusion": ["shall not include.*credential", "shall not include.*token.*api key"],
      "pii-minimization": ["minimum pii", "shall not expose.*not explicitly requested"],
      "log-redaction": ["shall not include.*password.*token.*pii", "redacted placeholder"],
      "safe-error-messages": ["generic error", "shall not expose.*stack trace"],
      "transport-encryption": ["tls", "shall not permit plaintext"],
      "csprng": ["cryptographically secure", "128 bits of entropy"],
      "strong-cryptography": ["aes-256", "shall not use.*md5.*sha-1"],
      "secrets-management": ["secrets manager", "environment variable", "shall not include.*source code"],
      "payload-signature-verification": ["verify.*signature", "hmac", "reject.*invalid signature"],
      "encryption-at-rest": ["encrypt.*at rest", "aes-256", "key management"],
      "file-type-validation": ["magic bytes", "mime type", "allowlist.*permitted"],
      "upload-storage-isolation": ["maximum file size", "outside.*document root", "randomized filename"],
      "path-canonicalization": ["canonical", "base directory", "traversal"],
      "safe-deserialization": ["schema.*validation", "shall not.*native object deserialization"],
      "redirect-allowlist": ["allowlist.*permitted domains", "shall not.*redirect.*arbitrary"],
      "resource-limits": ["maximum.*size", "rate limit", "429", "413"],
      "ssrf-prevention": ["allowlist.*schemes", "rfc-1918", "private address", "link-local"],
      "secure-defaults": ["disable.*default", "secure defaults"],
      "cors-restriction": ["cors", "allowlist.*trusted origins", "shall not.*wildcard"],
      "clickjacking-prevention": ["x-frame-options", "frame-ancestors"],
      "dependency-hygiene": ["no known.*cve", "vulnerability scanning"],
      "atomic-operation": ["exclusive lock", "atomic", "compare-and-swap"],
      "resource-quotas": ["quota", "per-user.*limit", "per-tenant"],
      "workflow-enforcement": ["valid predecessor state", "prerequisite steps"],
      "abuse-rate-limiting": ["frequency limit", "anomalous pattern"],
      "csv-formula-neutralization": ["prefix.*single-quote", "formula injection"],
      "origin-verification": ["verify.*origin", "mutual tls", "cryptographic signature"],
      "xxe-prevention": ["disable.*external entity", "dtd processing"],
      "no-dynamic-eval": ["shall not evaluate.*user.*as.*code", "sandboxed"],
      "template-injection-prevention": ["shall not interpolate.*user.*into.*template", "data-binding context"],
      "least-privilege": ["minimum privilege", "shall not run.*as root"],
      "command-parameterization": ["shall not pass.*user.*to.*command", "allowlisted command"],
    };

    return indicatorMap[primitive] ?? this.extractFromTemplate(template);
  }

  private extractFromTemplate(template: string): string[] {
    const shallClauses = template
      .split(/\.\s*/)
      .filter((s) => s.includes("SHALL"))
      .map((s) => s.toLowerCase().trim());
    return shallClauses.length > 0 ? shallClauses : [template.toLowerCase()];
  }
}

export interface CoverageGap {
  cweId: string;
  cweName: string;
  severity: "critical" | "high" | "medium" | "low";
  missingPrimitive: string;
  constraintId: string;
  suggestedTemplate: string;
  rationale: string;
}
