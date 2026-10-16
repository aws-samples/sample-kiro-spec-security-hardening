import type { CWEMapping } from "../types/index.js";

export const authorizationMappings: CWEMapping[] = [
  {
    id: "CWE-862",
    name: "Missing Authorization",
    description: "The product does not perform an authorization check when an actor accesses a resource",
    owaspCategory: "A01:2021-Broken Access Control",
    severity: "critical",
    tags: ["authorization", "access-control", "ownership-verification"],
    triggerConditions: [
      {
        id: "TC-862-1",
        description: "Requirement returns or mutates a resource owned by a principal",
        keywords: ["access", "view", "read", "update", "delete", "modify", "resource", "record", "data", "account"],
        semanticPatterns: [
          "user.*access.*resource",
          "return.*data.*for.*user",
          "view.*record",
          "update.*profile|account|settings",
          "delete.*resource",
          "modify.*owned.*by",
          "fetch.*by.*id|identifier",
        ],
        dataFlowIndicators: ["user-supplied ID → resource lookup", "request → data belonging to principal"],
      },
    ],
    earsConstraints: [
      {
        id: "EC-862-1",
        pattern: "ubiquitous",
        template: "THE SYSTEM SHALL verify that the requesting principal's identity matches the resource owner or holds an explicit permission grant before executing the operation.",
        securityPrimitive: "ownership-verification",
        rationale: "BOLA/IDOR vulnerabilities arise when object access lacks ownership checks.",
      },
      {
        id: "EC-862-2",
        pattern: "unwanted-behavior",
        template: "IF the requesting principal does not own or have explicit permission to access the resource, THEN THE SYSTEM SHALL return HTTP 403 with no data payload.",
        securityPrimitive: "authorization-denial",
        rationale: "Fail-closed authorization prevents any data leakage on unauthorized access.",
      },
    ],
  },
  {
    id: "CWE-863",
    name: "Incorrect Authorization",
    description: "The product performs an authorization check but does so incorrectly",
    owaspCategory: "A01:2021-Broken Access Control",
    severity: "critical",
    tags: ["authorization", "access-control", "role-check"],
    triggerConditions: [
      {
        id: "TC-863-1",
        description: "Requirement involves role-based operations on shared resources",
        keywords: ["role", "admin", "manager", "permission", "privilege", "elevated", "restricted"],
        semanticPatterns: [
          "admin.*can.*modify",
          "only.*manager.*may",
          "restricted.*to.*role",
          "elevated.*privilege",
          "role-based.*access",
        ],
      },
    ],
    earsConstraints: [
      {
        id: "EC-863-1",
        pattern: "event-driven",
        template: "WHILE {operation} on {resource} is being executed for {actor}, THE SYSTEM SHALL verify the actor holds the {required_role} role. WHILE {operation} on {resource} is being executed for {actor}, THE SYSTEM SHALL verify the role assignment is current.",
        securityPrimitive: "role-verification",
        rationale: "Stale or incorrectly checked role assignments enable privilege escalation.",
      },
    ],
  },
  {
    id: "CWE-639",
    name: "Authorization Bypass Through User-Controlled Key",
    description: "The system uses a user-controlled key to determine authorization without verifying ownership",
    owaspCategory: "A01:2021-Broken Access Control",
    severity: "critical",
    tags: ["authorization", "idor", "user-controlled-key"],
    triggerConditions: [
      {
        id: "TC-639-1",
        description: "Requirement uses a user-supplied identifier to look up resources",
        keywords: ["id", "identifier", "key", "reference", "lookup", "by id", "report id", "order id"],
        semanticPatterns: [
          "by.*identifier",
          "by.*id",
          "lookup.*by.*key",
          "access.*by.*report.*id",
          "fetch.*using.*user.*supplied.*id",
        ],
        dataFlowIndicators: ["user-controlled ID → resource fetch"],
      },
    ],
    earsConstraints: [
      {
        id: "EC-639-1",
        pattern: "event-driven",
        template: "WHILE a resource requested by identifier is being processed for {actor}, THE SYSTEM SHALL verify that the resource's owning tenant or principal matches the authenticated caller's identity.",
        securityPrimitive: "idor-prevention",
        rationale: "User-controlled keys without ownership validation enable horizontal privilege escalation (BOLA).",
      },
    ],
  },
  {
    id: "CWE-352",
    name: "Cross-Site Request Forgery (CSRF)",
    description: "The product does not verify that a request was intentionally made by the user",
    owaspCategory: "A01:2021-Broken Access Control",
    severity: "high",
    tags: ["authorization", "csrf", "state-mutation"],
    triggerConditions: [
      {
        id: "TC-352-1",
        description: "Requirement involves state-mutating HTTP endpoint",
        keywords: ["create", "update", "delete", "modify", "submit", "post", "transfer", "change"],
        semanticPatterns: [
          "submit.*form",
          "create.*resource",
          "update.*setting",
          "delete.*record",
          "transfer.*funds",
          "change.*password",
          "modify.*configuration",
        ],
        dataFlowIndicators: ["browser form → state change"],
      },
    ],
    earsConstraints: [
      {
        id: "EC-352-1",
        pattern: "ubiquitous",
        template: "THE SYSTEM SHALL validate a CSRF token on all state-mutating requests. THE SYSTEM SHALL reject requests with a missing or invalid token with HTTP 403.",
        securityPrimitive: "csrf-protection",
        rationale: "CSRF tokens prevent cross-origin requests from executing state changes on behalf of authenticated users.",
      },
    ],
  },
  {
    id: "CWE-269",
    name: "Improper Privilege Management",
    description: "The product does not properly manage privileges, allowing escalation",
    owaspCategory: "A01:2021-Broken Access Control",
    severity: "critical",
    tags: ["authorization", "privilege-escalation", "least-privilege"],
    triggerConditions: [
      {
        id: "TC-269-1",
        description: "Requirement involves privilege assignment or role change",
        keywords: ["assign", "grant", "elevate", "promote", "role change", "permission", "admin access"],
        semanticPatterns: [
          "assign.*role",
          "grant.*permission",
          "elevate.*privilege",
          "promote.*to.*admin",
          "change.*role",
        ],
      },
    ],
    earsConstraints: [
      {
        id: "EC-269-1",
        pattern: "event-driven",
        template: "WHEN {actor} requests a privilege escalation for {target}, THE SYSTEM SHALL verify the actor holds a super-set of the target privilege AND SHALL log the privilege change to an immutable audit trail.",
        securityPrimitive: "privilege-escalation-control",
        rationale: "Unchecked privilege assignment enables vertical escalation attacks.",
      },
    ],
  },
  {
    id: "CWE-284",
    name: "Improper Access Control",
    description: "The product does not restrict or incorrectly restricts access to a resource",
    owaspCategory: "A01:2021-Broken Access Control",
    severity: "high",
    tags: ["authorization", "access-control", "multi-tenant"],
    triggerConditions: [
      {
        id: "TC-284-1",
        description: "Requirement involves multi-tenant data access",
        keywords: ["tenant", "organization", "company", "workspace", "team", "account scope"],
        semanticPatterns: [
          "tenant.*data",
          "organization.*resource",
          "scoped.*to.*workspace",
          "within.*team",
          "cross-tenant",
        ],
        dataFlowIndicators: ["request → data from another tenant's scope"],
      },
    ],
    earsConstraints: [
      {
        id: "EC-284-1",
        pattern: "ubiquitous",
        template: "THE SYSTEM SHALL enforce tenant isolation by including the authenticated user's tenant_id as a mandatory filter in all data queries. THE SYSTEM SHALL NOT return data belonging to a different tenant under any condition.",
        securityPrimitive: "tenant-isolation",
        rationale: "Multi-tenant systems without mandatory tenant scoping enable cross-tenant data access.",
      },
    ],
  },
];
