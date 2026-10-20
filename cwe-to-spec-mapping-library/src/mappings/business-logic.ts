import type { CWEMapping } from "../types/index.js";

export const businessLogicMappings: CWEMapping[] = [
  {
    id: "CWE-362",
    name: "Race Condition",
    description: "The product contains a concurrent execution flow that allows improper resource access",
    owaspCategory: "A04:2021-Insecure Design",
    severity: "high",
    tags: ["business-logic", "concurrency", "race-condition", "toctou"],
    triggerConditions: [
      {
        id: "TC-362-1",
        description: "Requirement involves check-then-act on shared resources or financial operations",
        keywords: ["balance", "inventory", "stock", "quota", "limit", "available", "reserve", "deduct", "transfer"],
        semanticPatterns: [
          "check.*balance.*then.*deduct",
          "verify.*availability.*then.*reserve",
          "check.*stock.*then.*purchase",
          "if.*sufficient.*then.*transfer",
          "concurrent.*access",
        ],
        dataFlowIndicators: ["read state → make decision → mutate state"],
      },
    ],
    earsConstraints: [
      {
        id: "EC-362-1",
        pattern: "event-driven",
        template: "WHEN {actor} requests to {operation} on a shared resource, THE SYSTEM SHALL acquire an exclusive lock or use an atomic compare-and-swap operation to prevent concurrent modification between the validation check and the state mutation.",
        securityPrimitive: "atomic-operation",
        rationale: "TOCTOU race conditions enable double-spending, over-allocation, and inconsistent state.",
      },
    ],
  },
  {
    id: "CWE-770",
    name: "Allocation of Resources Without Limits or Throttling",
    description: "The product allocates resources without any mechanism to limit the size or number",
    owaspCategory: "A04:2021-Insecure Design",
    severity: "medium",
    tags: ["business-logic", "resource-exhaustion", "dos"],
    triggerConditions: [
      {
        id: "TC-770-1",
        description: "Requirement allocates resources based on user request",
        keywords: ["create", "allocate", "provision", "spawn", "generate", "queue", "schedule"],
        semanticPatterns: [
          "create.*resources.*per.*request",
          "allocate.*on.*demand",
          "provision.*for.*each",
          "spawn.*worker",
          "generate.*report",
        ],
      },
    ],
    earsConstraints: [
      {
        id: "EC-770-1",
        pattern: "ubiquitous",
        template: "THE SYSTEM SHALL enforce per-user and per-tenant quotas for resource allocation. THE SYSTEM SHALL reject allocation requests that would exceed the configured quota with a clear limit-exceeded error.",
        securityPrimitive: "resource-quotas",
        rationale: "Unbounded resource allocation enables single-user denial-of-service against shared infrastructure.",
      },
    ],
  },
  {
    id: "CWE-841",
    name: "Improper Enforcement of Behavioral Workflow",
    description: "The product does not enforce a required sequence of operations",
    owaspCategory: "A04:2021-Insecure Design",
    severity: "high",
    tags: ["business-logic", "workflow", "state-machine"],
    triggerConditions: [
      {
        id: "TC-841-1",
        description: "Requirement involves multi-step workflows or state transitions",
        keywords: ["workflow", "step", "process", "state", "transition", "approve", "submit", "finalize"],
        semanticPatterns: [
          "after.*approval.*then",
          "must.*complete.*step.*before",
          "transition.*from.*to",
          "workflow.*state",
          "multi-step.*process",
        ],
      },
    ],
    earsConstraints: [
      {
        id: "EC-841-1",
        pattern: "event-driven",
        template: "WHILE a requested transition to state {target_state} is being allowed for {actor}, THE SYSTEM SHALL verify the resource is currently in a valid predecessor state. WHILE a requested transition to state {target_state} is being allowed for {actor}, THE SYSTEM SHALL verify the actor has completed all prerequisite steps.",
        securityPrimitive: "workflow-enforcement",
        rationale: "Skipping workflow steps enables bypassing validation, approval, or payment gates.",
      },
    ],
  },
  {
    id: "CWE-799",
    name: "Improper Control of Interaction Frequency",
    description: "The product does not properly limit the frequency of interactions by an actor",
    owaspCategory: "A04:2021-Insecure Design",
    severity: "medium",
    tags: ["business-logic", "rate-limiting", "abuse-prevention"],
    triggerConditions: [
      {
        id: "TC-799-1",
        description: "Requirement involves high-value or abuse-prone operations",
        keywords: ["purchase", "vote", "comment", "review", "coupon", "referral", "reward", "claim"],
        semanticPatterns: [
          "submit.*vote",
          "apply.*coupon",
          "claim.*reward",
          "post.*review",
          "make.*purchase",
          "use.*referral",
        ],
      },
    ],
    earsConstraints: [
      {
        id: "EC-799-1",
        pattern: "event-driven",
        template: "WHEN {actor} performs {high_value_operation}, THE SYSTEM SHALL enforce per-user frequency limits appropriate to the operation AND SHALL flag anomalous patterns for review.",
        securityPrimitive: "abuse-rate-limiting",
        rationale: "Unthrottled high-value operations enable reward abuse, ballot stuffing, and economic exploitation.",
      },
    ],
  },
  {
    id: "CWE-1236",
    name: "Improper Neutralization of Formula Elements in a CSV File",
    description: "The product generates CSV output containing formulas that execute when opened in a spreadsheet",
    owaspCategory: "A03:2021-Injection",
    severity: "medium",
    tags: ["business-logic", "csv-injection", "export"],
    triggerConditions: [
      {
        id: "TC-1236-1",
        description: "Requirement exports data as CSV or spreadsheet format",
        keywords: ["export", "csv", "spreadsheet", "excel", "download", "report"],
        semanticPatterns: [
          "export.*csv",
          "download.*spreadsheet",
          "generate.*excel",
          "export.*report",
        ],
      },
    ],
    earsConstraints: [
      {
        id: "EC-1236-1",
        pattern: "event-driven",
        template: "WHEN the system generates CSV output containing user-supplied data, THE SYSTEM SHALL prefix any cell value starting with =, +, -, or @ with a single-quote character to prevent formula injection.",
        securityPrimitive: "csv-formula-neutralization",
        rationale: "CSV injection enables remote code execution when exported files are opened in spreadsheet applications.",
      },
    ],
  },
  {
    id: "CWE-346",
    name: "Origin Validation Error",
    description: "The product does not properly verify that the source of data or communication is valid",
    owaspCategory: "A07:2021-Identification and Authentication Failures",
    severity: "high",
    tags: ["business-logic", "origin-validation", "trust-boundary"],
    triggerConditions: [
      {
        id: "TC-346-1",
        description: "Requirement processes messages or events from external sources",
        keywords: ["message", "event", "notification", "queue", "pubsub", "webhook", "callback"],
        semanticPatterns: [
          "process.*message.*from",
          "handle.*event.*from",
          "receive.*notification",
          "consume.*from.*queue",
        ],
      },
    ],
    earsConstraints: [
      {
        id: "EC-346-1",
        pattern: "event-driven",
        template: "WHILE a message received from an external source is being processed, THE SYSTEM SHALL verify the message origin through a cryptographic signature or mutual TLS.",
        securityPrimitive: "origin-verification",
        rationale: "Unverified message origins enable injection of forged commands into the system.",
      },
    ],
  },
  {
    id: "CWE-1333",
    name: "Inefficient Regular Expression Complexity (ReDoS)",
    description: "A regular expression with super-linear worst-case runtime can be driven to denial of service by crafted input",
    owaspCategory: "A05:2021-Security Misconfiguration",
    severity: "medium",
    tags: ["business-logic", "denial-of-service", "regex", "input-validation"],
    triggerConditions: [
      {
        id: "TC-1333-1",
        description: "Requirement matches user-supplied input against a regular expression",
        keywords: ["regex", "regular expression", "pattern match", "validate format", "match pattern"],
        semanticPatterns: [
          "match.*input.*against.*pattern",
          "validate.*format.*with.*regex",
          "parse.*using.*regular expression",
        ],
        dataFlowIndicators: ["user input → regex engine"],
      },
    ],
    earsConstraints: [
      {
        id: "EC-1333-1",
        pattern: "ubiquitous",
        template: "THE SYSTEM SHALL evaluate user-supplied input only against regular expressions verified to have linear worst-case matching complexity.",
        securityPrimitive: "safe-regex",
        rationale: "A pattern with catastrophic backtracking lets a short crafted string consume unbounded CPU.",
      },
      {
        id: "EC-1333-2",
        pattern: "event-driven",
        template: "WHEN input is matched against a regular expression, THE SYSTEM SHALL enforce a bounded execution timeout on the match operation.",
        securityPrimitive: "regex-timeout",
        rationale: "A hard timeout caps the damage of any pattern that still exhibits pathological backtracking.",
      },
    ],
  },
  {
    id: "CWE-409",
    name: "Improper Handling of Highly Compressed Data (Zip Bomb)",
    description: "Decompressing untrusted archives without limits enables data-amplification denial of service",
    owaspCategory: "A05:2021-Security Misconfiguration",
    severity: "medium",
    tags: ["business-logic", "denial-of-service", "decompression", "resource-limit"],
    triggerConditions: [
      {
        id: "TC-409-1",
        description: "Requirement decompresses or extracts an uploaded or fetched archive",
        keywords: ["decompress", "unzip", "extract", "archive", "zip", "gzip", "tar", "inflate"],
        semanticPatterns: [
          "extract.*uploaded.*archive",
          "decompress.*file",
          "unzip.*user.*upload",
          "inflate.*compressed.*payload",
        ],
        dataFlowIndicators: ["uploaded archive → decompression"],
      },
    ],
    earsConstraints: [
      {
        id: "EC-409-1",
        pattern: "state-driven",
        template: "WHILE decompressing untrusted archive data, THE SYSTEM SHALL enforce limits on the total uncompressed size, entry count, and compression ratio.",
        securityPrimitive: "decompression-limits",
        rationale: "Bounding the decompressed output prevents a small crafted archive from exhausting memory or disk.",
      },
      {
        id: "EC-409-2",
        pattern: "unwanted-behavior",
        template: "IF a decompression limit is exceeded, THEN THE SYSTEM SHALL abort the extraction and discard the partial output.",
        securityPrimitive: "fail-closed-decompression",
        rationale: "Aborting on a limit breach stops the amplification attack in progress.",
      },
    ],
  },
];
