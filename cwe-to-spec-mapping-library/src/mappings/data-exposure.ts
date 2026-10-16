import type { CWEMapping } from "../types/index.js";

export const dataExposureMappings: CWEMapping[] = [
  {
    id: "CWE-200",
    name: "Exposure of Sensitive Information to an Unauthorized Actor",
    description: "The product exposes sensitive information to an actor not explicitly authorized to have access",
    owaspCategory: "A01:2021-Broken Access Control",
    severity: "high",
    tags: ["data-exposure", "information-disclosure", "sensitive-data"],
    triggerConditions: [
      {
        id: "TC-200-1",
        description: "Requirement returns data that may contain sensitive fields",
        keywords: ["return", "display", "expose", "send", "response", "payload", "data", "details"],
        semanticPatterns: [
          "return.*all.*data",
          "send.*full.*payload",
          "expose.*details",
          "return.*user.*information",
          "display.*account.*details",
        ],
        dataFlowIndicators: ["internal data → external response"],
      },
    ],
    earsConstraints: [
      {
        id: "EC-200-1",
        pattern: "ubiquitous",
        template: "THE SYSTEM SHALL return only the minimum fields required for the operation. THE SYSTEM SHALL NOT expose internal identifiers, system metadata, or fields not explicitly requested by the caller.",
        securityPrimitive: "data-minimization",
        rationale: "Over-broad responses leak internal state and sensitive data to external consumers.",
      },
    ],
  },
  {
    id: "CWE-201",
    name: "Insertion of Sensitive Information Into Sent Data",
    description: "The product sends data to a downstream component that includes sensitive information not needed by that component",
    owaspCategory: "A04:2021-Insecure Design",
    severity: "high",
    tags: ["data-exposure", "sensitive-data", "outbound-payload"],
    triggerConditions: [
      {
        id: "TC-201-1",
        description: "Requirement sends payloads to external services or webhooks",
        keywords: ["webhook", "callback", "notify", "post to", "send to", "external", "integration", "third-party"],
        semanticPatterns: [
          "send.*payload.*to.*external",
          "post.*to.*webhook",
          "notify.*third.*party",
          "deliver.*to.*customer.*endpoint",
          "integration.*callback",
        ],
        dataFlowIndicators: ["internal data → external endpoint"],
      },
    ],
    earsConstraints: [
      {
        id: "EC-201-1",
        pattern: "event-driven",
        template: "WHEN the system delivers data to an external endpoint, THE SYSTEM SHALL include only an explicit allowlist of non-credential, non-PII fields in the outbound payload.",
        securityPrimitive: "outbound-data-allowlist",
        rationale: "Outbound payloads to external endpoints risk credential and PII leakage through over-serialization.",
      },
      {
        id: "EC-201-2",
        pattern: "unwanted-behavior",
        template: "THE SYSTEM SHALL NOT include any credential, token, API key, secret, or PII field in outbound webhook or callback payloads.",
        securityPrimitive: "credential-exclusion",
        rationale: "Credentials in outbound payloads to customer-controlled endpoints are irrecoverably compromised.",
      },
    ],
  },
  {
    id: "CWE-359",
    name: "Exposure of Private Personal Information to an Unauthorized Actor",
    description: "The product exposes PII to actors not authorized to access it",
    owaspCategory: "A01:2021-Broken Access Control",
    severity: "high",
    tags: ["data-exposure", "pii", "privacy", "gdpr"],
    triggerConditions: [
      {
        id: "TC-359-1",
        description: "Requirement returns user profile or personal data",
        keywords: ["profile", "personal", "user data", "account info", "contact", "address", "email", "phone", "ssn"],
        semanticPatterns: [
          "return.*user.*profile",
          "display.*personal.*data",
          "show.*account.*information",
          "expose.*contact.*details",
          "list.*user.*records",
        ],
      },
    ],
    earsConstraints: [
      {
        id: "EC-359-1",
        pattern: "ubiquitous",
        template: "THE SYSTEM SHALL return only the minimum PII fields required for the operation. THE SYSTEM SHALL NOT expose fields not explicitly requested by the calling principal.",
        securityPrimitive: "pii-minimization",
        rationale: "PII exposure violates privacy regulations (GDPR Art.5(1)(c)) and increases breach impact.",
      },
    ],
  },
  {
    id: "CWE-532",
    name: "Insertion of Sensitive Information into Log File",
    description: "The product writes sensitive information to a log file",
    owaspCategory: "A09:2021-Security Logging and Monitoring Failures",
    severity: "high",
    tags: ["data-exposure", "logging", "sensitive-data", "pii"],
    triggerConditions: [
      {
        id: "TC-532-1",
        description: "Requirement involves logging, auditing, or tracing",
        keywords: ["log", "audit", "trace", "monitor", "record", "track", "debug", "observability"],
        semanticPatterns: [
          "log.*request",
          "audit.*action",
          "trace.*operation",
          "record.*event",
          "write.*to.*log",
          "emit.*metric",
        ],
      },
    ],
    earsConstraints: [
      {
        id: "EC-532-1",
        pattern: "ubiquitous",
        template: "THE SYSTEM SHALL NOT include passwords, tokens, PII, or financial instrument numbers in any log or trace output. THE SYSTEM SHALL replace all sensitive field values with a redacted placeholder before writing any log or trace record.",
        securityPrimitive: "log-redaction",
        rationale: "Sensitive data in logs persists in centralized logging systems accessible to operations staff and potentially attackers.",
      },
    ],
  },
  {
    id: "CWE-209",
    name: "Generation of Error Message Containing Sensitive Information",
    description: "The product generates error messages that include sensitive information about the system",
    owaspCategory: "A04:2021-Insecure Design",
    severity: "medium",
    tags: ["data-exposure", "error-handling", "information-disclosure"],
    triggerConditions: [
      {
        id: "TC-209-1",
        description: "Requirement involves error handling or error responses",
        keywords: ["error", "exception", "failure", "invalid", "reject", "deny", "fail"],
        semanticPatterns: [
          "return.*error.*message",
          "display.*error",
          "handle.*exception",
          "respond.*with.*failure",
        ],
      },
    ],
    earsConstraints: [
      {
        id: "EC-209-1",
        pattern: "ubiquitous",
        template: "THE SYSTEM SHALL return generic error messages to external callers. THE SYSTEM SHALL NOT expose stack traces, internal paths, database schema details, or configuration values in error responses.",
        securityPrimitive: "safe-error-messages",
        rationale: "Detailed error messages reveal internal architecture to attackers, aiding exploitation.",
      },
    ],
  },
  {
    id: "CWE-319",
    name: "Cleartext Transmission of Sensitive Information",
    description: "The product transmits sensitive data in cleartext within a communication channel",
    owaspCategory: "A02:2021-Cryptographic Failures",
    severity: "high",
    tags: ["data-exposure", "encryption", "transport-security"],
    triggerConditions: [
      {
        id: "TC-319-1",
        description: "Requirement transmits data to external systems",
        keywords: ["send", "transmit", "deliver", "post", "webhook", "callback", "api call", "request"],
        semanticPatterns: [
          "send.*to.*endpoint",
          "transmit.*data",
          "deliver.*payload",
          "call.*external.*service",
        ],
        dataFlowIndicators: ["sensitive data → network transmission"],
      },
    ],
    earsConstraints: [
      {
        id: "EC-319-1",
        pattern: "ubiquitous",
        template: "THE SYSTEM SHALL transmit all sensitive data exclusively over TLS 1.2 or higher. THE SYSTEM SHALL NOT permit plaintext HTTP for any endpoint handling sensitive information.",
        securityPrimitive: "transport-encryption",
        rationale: "Cleartext transmission exposes sensitive data to network-level interception.",
      },
    ],
  },
];
