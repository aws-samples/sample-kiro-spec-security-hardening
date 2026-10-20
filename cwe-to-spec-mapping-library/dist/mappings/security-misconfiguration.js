export const securityMisconfigurationMappings = [
    {
        id: "CWE-269",
        name: "Improper Privilege Management",
        description: "The product does not properly assign, modify, track, or check privileges",
        owaspCategory: "A05:2021-Security Misconfiguration",
        severity: "high",
        tags: ["misconfiguration", "privilege", "least-privilege"],
        triggerConditions: [
            {
                id: "TC-269-2",
                description: "Requirement runs operations with elevated privileges",
                keywords: ["admin", "root", "system", "elevated", "privileged", "service account"],
                semanticPatterns: [
                    "run.*as.*admin",
                    "execute.*with.*system.*privileges",
                    "service.*account",
                    "elevated.*context",
                ],
            },
        ],
        earsConstraints: [
            {
                id: "EC-269-2",
                pattern: "ubiquitous",
                template: "THE SYSTEM SHALL execute all operations with the minimum privilege level required. THE SYSTEM SHALL NOT run application processes as root or with administrative privileges unless explicitly required and documented.",
                securityPrimitive: "least-privilege",
                rationale: "Excessive privileges amplify the impact of any vulnerability to full system compromise.",
            },
        ],
    },
    {
        id: "CWE-16",
        name: "Configuration",
        description: "Weaknesses related to system configuration that can be exploited",
        owaspCategory: "A05:2021-Security Misconfiguration",
        severity: "medium",
        tags: ["misconfiguration", "defaults", "hardening"],
        triggerConditions: [
            {
                id: "TC-16-1",
                description: "Requirement involves deployment or configuration of services",
                keywords: ["deploy", "configure", "setup", "provision", "initialize", "install"],
                semanticPatterns: [
                    "deploy.*service",
                    "configure.*server",
                    "provision.*infrastructure",
                    "initialize.*application",
                ],
            },
        ],
        earsConstraints: [
            {
                id: "EC-16-1",
                pattern: "ubiquitous",
                template: "THE SYSTEM SHALL ship with no default accounts, sample data, or unnecessary features enabled. THE SYSTEM SHALL enforce secure defaults for all configuration parameters.",
                securityPrimitive: "secure-defaults",
                rationale: "Default configurations are publicly documented and are the first target of automated attacks.",
            },
        ],
    },
    {
        id: "CWE-942",
        name: "Permissive Cross-domain Policy with Untrusted Domains",
        description: "The product uses a cross-domain policy that is too permissive",
        owaspCategory: "A05:2021-Security Misconfiguration",
        severity: "medium",
        tags: ["misconfiguration", "cors", "cross-origin"],
        requiresContext: ["http"],
        triggerConditions: [
            {
                id: "TC-942-1",
                description: "Requirement serves API responses to browser-based clients from different origins",
                keywords: ["api", "cors", "cross-origin", "frontend", "spa", "browser", "ajax"],
                semanticPatterns: [
                    "serve.*api.*to.*frontend",
                    "cross-origin.*request",
                    "browser.*client.*calls",
                    "single.*page.*app.*consumes",
                ],
            },
        ],
        earsConstraints: [
            {
                id: "EC-942-1",
                pattern: "ubiquitous",
                template: "THE SYSTEM SHALL configure CORS to allow only an explicit allowlist of trusted origins. THE SYSTEM SHALL NOT use wildcard (*) Access-Control-Allow-Origin headers on authenticated endpoints.",
                securityPrimitive: "cors-restriction",
                rationale: "Permissive CORS policies enable cross-origin data theft from authenticated sessions.",
            },
        ],
    },
    {
        id: "CWE-1021",
        name: "Improper Restriction of Rendered UI Layers or Frames",
        description: "The product does not restrict or incorrectly restricts frame embedding",
        owaspCategory: "A05:2021-Security Misconfiguration",
        severity: "medium",
        tags: ["misconfiguration", "clickjacking", "framing"],
        requiresContext: ["html"],
        triggerConditions: [
            {
                id: "TC-1021-1",
                description: "Requirement serves web pages with interactive UI actions",
                keywords: ["page", "ui", "form", "button", "action", "web interface", "dashboard"],
                semanticPatterns: [
                    "display.*web.*interface",
                    "render.*dashboard",
                    "present.*form",
                    "interactive.*page",
                ],
            },
        ],
        earsConstraints: [
            {
                id: "EC-1021-1",
                pattern: "ubiquitous",
                template: "THE SYSTEM SHALL set X-Frame-Options to DENY (or SAMEORIGIN where framing is required) and SHALL include a Content-Security-Policy frame-ancestors directive on all HTML responses.",
                securityPrimitive: "clickjacking-prevention",
                rationale: "Unrestricted framing enables clickjacking attacks that trick users into performing unintended actions.",
            },
        ],
    },
    {
        id: "CWE-1104",
        name: "Use of Unmaintained Third-Party Components",
        description: "The product relies on third-party components that are no longer maintained",
        owaspCategory: "A06:2021-Vulnerable and Outdated Components",
        severity: "medium",
        tags: ["misconfiguration", "dependencies", "supply-chain"],
        triggerConditions: [
            {
                id: "TC-1104-1",
                description: "Requirement introduces third-party dependencies",
                keywords: ["library", "package", "dependency", "framework", "sdk", "plugin", "module"],
                semanticPatterns: [
                    "use.*library",
                    "integrate.*sdk",
                    "depend.*on.*package",
                    "install.*framework",
                ],
            },
        ],
        earsConstraints: [
            {
                id: "EC-1104-1",
                pattern: "ubiquitous",
                template: "THE SYSTEM SHALL use only actively maintained dependencies with no known critical or high CVEs. THE SYSTEM SHALL enforce automated vulnerability scanning of all transitive dependencies in the CI pipeline.",
                securityPrimitive: "dependency-hygiene",
                rationale: "Unmaintained components accumulate unpatched vulnerabilities that attackers actively exploit.",
            },
        ],
    },
    {
        id: "CWE-732",
        name: "Incorrect Permission Assignment for Critical Resource",
        description: "A security-critical resource is created with overly permissive access permissions",
        owaspCategory: "A05:2021-Security Misconfiguration",
        severity: "high",
        tags: ["security-misconfiguration", "file-permissions", "least-privilege", "access-control"],
        triggerConditions: [
            {
                id: "TC-732-1",
                description: "Requirement creates a file, directory, or resource that holds sensitive data or configuration",
                keywords: ["create file", "write file", "directory", "permissions", "config file", "key file", "credential file", "world-readable"],
                semanticPatterns: [
                    "create.*file.*with.*permissions",
                    "write.*configuration.*to.*disk",
                    "store.*key.*in.*file",
                    "set.*file.*access",
                ],
                dataFlowIndicators: ["sensitive resource → filesystem permissions"],
            },
        ],
        earsConstraints: [
            {
                id: "EC-732-1",
                pattern: "ubiquitous",
                template: "THE SYSTEM SHALL create files and directories holding sensitive data with the most restrictive permissions that still permit correct operation, granting no access to group or other principals by default.",
                securityPrimitive: "least-privilege-permissions",
                rationale: "World- or group-readable permissions on secret or configuration files expose them to any local account.",
            },
        ],
    },
    {
        id: "CWE-377",
        name: "Insecure Temporary File",
        description: "Temporary files created in a shared location with predictable names are vulnerable to tampering and race conditions",
        owaspCategory: "A05:2021-Security Misconfiguration",
        severity: "medium",
        tags: ["security-misconfiguration", "temporary-file", "race-condition", "file-permissions"],
        triggerConditions: [
            {
                id: "TC-377-1",
                description: "Requirement creates temporary files or working directories",
                keywords: ["temporary file", "temp file", "scratch file", "working directory", "cache file", "intermediate file"],
                semanticPatterns: [
                    "create.*temporary.*file",
                    "write.*to.*temp",
                    "generate.*scratch.*file",
                    "store.*intermediate.*data.*on.*disk",
                ],
                dataFlowIndicators: ["data → temporary file"],
            },
        ],
        earsConstraints: [
            {
                id: "EC-377-1",
                pattern: "ubiquitous",
                template: "THE SYSTEM SHALL create temporary files atomically in a private, access-restricted directory using unpredictable, randomly generated names.",
                securityPrimitive: "secure-temp-file",
                rationale: "Predictable names or shared directories let a local attacker pre-create, read, or swap the file through a race condition.",
            },
        ],
    },
    {
        id: "CWE-489",
        name: "Active Debug Code",
        description: "Debugging features left enabled in production expose internal state and management functions",
        owaspCategory: "A05:2021-Security Misconfiguration",
        severity: "medium",
        tags: ["security-misconfiguration", "debug", "hardening", "production"],
        triggerConditions: [
            {
                id: "TC-489-1",
                description: "Requirement references debug, verbose, or developer modes, or diagnostic endpoints",
                keywords: ["debug", "debug mode", "verbose", "developer mode", "debugger", "test endpoint", "diagnostic"],
                semanticPatterns: [
                    "enable.*debug",
                    "run.*in.*development.*mode",
                    "expose.*diagnostic.*endpoint",
                    "show.*detailed.*errors",
                ],
            },
        ],
        earsConstraints: [
            {
                id: "EC-489-1",
                pattern: "ubiquitous",
                template: "THE SYSTEM SHALL disable debug modes, verbose diagnostics, and developer or test endpoints in all production deployments.",
                securityPrimitive: "debug-disabled-in-prod",
                rationale: "Active debug code discloses stack traces and internal state and can expose unauthenticated management functionality.",
            },
        ],
    },
];
//# sourceMappingURL=security-misconfiguration.js.map