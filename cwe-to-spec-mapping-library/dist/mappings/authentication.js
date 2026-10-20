export const authenticationMappings = [
    {
        id: "CWE-306",
        name: "Missing Authentication for Critical Function",
        description: "The product does not perform any authentication for functionality that requires a provable user identity",
        owaspCategory: "A07:2021-Identification and Authentication Failures",
        severity: "critical",
        tags: ["authentication", "access-control", "endpoint-security"],
        triggerConditions: [
            {
                id: "TC-306-1",
                description: "Requirement exposes an endpoint or resource without specifying authentication",
                keywords: ["endpoint", "api", "resource", "service", "route", "page", "interface"],
                semanticPatterns: [
                    "expose.*endpoint",
                    "provide.*api",
                    "return.*data.*to.*user",
                    "allow.*access.*to",
                    "serve.*resource",
                    "the system shall.*(?:return|provide|display|show)",
                ],
                dataFlowIndicators: ["external request → internal resource"],
            },
        ],
        earsConstraints: [
            {
                id: "EC-306-1",
                pattern: "unwanted-behavior",
                template: "IF a request that the specification does not explicitly allow without authentication arrives without a valid authenticated session or signed token, THEN THE SYSTEM SHALL reject the request.",
                securityPrimitive: "authentication-required",
                rationale: "Every request that serves non-public data must verify the caller's identity. Requests the spec deliberately leaves open, such as registration and login, stay exempt.",
            },
            {
                id: "EC-306-2",
                pattern: "unwanted-behavior",
                template: "IF a request is rejected for missing authentication, THEN THE SYSTEM SHALL return no protected data in the rejection AND SHALL NOT process the request further.",
                securityPrimitive: "authentication-enforcement",
                rationale: "Fail-closed authentication prevents any data leakage on unauthenticated access.",
            },
        ],
    },
    {
        id: "CWE-307",
        name: "Improper Restriction of Excessive Authentication Attempts",
        description: "The product does not implement sufficient measures to prevent multiple failed authentication attempts",
        owaspCategory: "A07:2021-Identification and Authentication Failures",
        severity: "high",
        tags: ["authentication", "brute-force", "rate-limiting"],
        triggerConditions: [
            {
                id: "TC-307-1",
                description: "Requirement involves login, password reset, or OTP endpoint",
                keywords: ["login", "sign in", "authenticate", "password", "otp", "verification code", "mfa", "reset"],
                semanticPatterns: [
                    "user.*log.*in",
                    "authenticate.*with.*password",
                    "verify.*credentials",
                    "submit.*otp",
                    "reset.*password",
                    "verify.*identity",
                ],
            },
        ],
        earsConstraints: [
            {
                id: "EC-307-1",
                pattern: "event-driven",
                template: "WHEN authentication attempts exceed 5 failures per account per 60-second window, THE SYSTEM SHALL apply exponential back-off to subsequent attempts AND SHALL emit a brute-force audit event.",
                securityPrimitive: "rate-limiting",
                rationale: "Rate limiting makes credential stuffing and brute-force attacks economically infeasible.",
            },
            {
                id: "EC-307-2",
                pattern: "event-driven",
                template: "WHEN authentication attempts exceed 20 failures per IP address per 5-minute window, THE SYSTEM SHALL temporarily block that IP AND SHALL alert the security monitoring system.",
                securityPrimitive: "ip-rate-limiting",
                rationale: "IP-level throttling catches distributed credential attacks across multiple accounts.",
            },
        ],
    },
    {
        id: "CWE-208",
        name: "Observable Timing Discrepancy",
        description: "The product behaves differently based on whether a credential is valid, revealing information through timing",
        owaspCategory: "A07:2021-Identification and Authentication Failures",
        severity: "medium",
        tags: ["authentication", "timing-attack", "side-channel"],
        triggerConditions: [
            {
                id: "TC-208-1",
                description: "Requirement differentiates valid from invalid credentials in response behavior",
                keywords: ["authenticate", "verify", "credential", "password", "login", "validate identity"],
                semanticPatterns: [
                    "verify.*credential",
                    "check.*password",
                    "validate.*user.*identity",
                    "authenticate.*against",
                ],
            },
        ],
        earsConstraints: [
            {
                id: "EC-208-1",
                pattern: "ubiquitous",
                template: "THE SYSTEM SHALL return authentication responses in constant time regardless of whether the account exists or the credential is valid, using a dummy hash comparison when the account is not found.",
                securityPrimitive: "constant-time-comparison",
                rationale: "Timing differences reveal account existence, enabling targeted credential attacks.",
            },
        ],
    },
    {
        id: "CWE-522",
        name: "Insufficiently Protected Credentials",
        description: "The product transmits or stores authentication credentials in a manner susceptible to interception",
        owaspCategory: "A07:2021-Identification and Authentication Failures",
        severity: "critical",
        tags: ["authentication", "credential-storage", "hashing"],
        triggerConditions: [
            {
                id: "TC-522-1",
                description: "Requirement stores or verifies passwords",
                keywords: ["password", "credential", "store", "save", "persist", "hash", "verify"],
                semanticPatterns: [
                    "store.*password",
                    "save.*credential",
                    "persist.*user.*password",
                    "create.*account.*with.*password",
                    "register.*user",
                ],
            },
        ],
        earsConstraints: [
            {
                id: "EC-522-1",
                pattern: "ubiquitous",
                template: "THE SYSTEM SHALL store each password only as a salted hash computed with Argon2id using at least 19 MiB of memory, 2 iterations and a parallelism of 1. THE SYSTEM SHALL NOT store plaintext or reversibly-encrypted passwords.",
                appliesTo: "\\b(?:stores?|stored|storing|persist(?:s|ed)?|saves?|saved|hash(?:es|ed)?|password_hash)\\b",
                securityPrimitive: "password-hashing",
                rationale: "A memory-hard hash at OWASP's minimum Argon2id parameters makes offline cracking of a stolen credential store expensive. Bcrypt is avoided as the default because it silently truncates passwords longer than 72 bytes.",
            },
        ],
    },
    {
        id: "CWE-916",
        name: "Use of Password Hash With Insufficient Computational Effort",
        description: "The product uses a hash function without sufficient computational cost for password storage",
        owaspCategory: "A02:2021-Cryptographic Failures",
        severity: "high",
        tags: ["authentication", "password-hashing", "cryptography"],
        triggerConditions: [
            {
                id: "TC-916-1",
                description: "Requirement hashes passwords",
                keywords: ["hash", "password", "digest", "encrypt password", "store password"],
                semanticPatterns: [
                    "hash.*password",
                    "store.*hashed.*password",
                    "password.*storage",
                ],
            },
        ],
        earsConstraints: [
            {
                id: "EC-916-1",
                pattern: "ubiquitous",
                template: "THE SYSTEM SHALL use Argon2id, scrypt, or bcrypt exclusively for password hashing. THE SYSTEM SHALL NOT use bcrypt for passwords that can exceed 72 bytes, because bcrypt ignores every byte after the 72nd. THE SYSTEM SHALL NOT use MD5, SHA-1, or SHA-2 family for password hashing.",
                appliesTo: "\\b(?:stores?|stored|storing|persist(?:s|ed)?|saves?|saved|hash(?:es|ed)?|password_hash)\\b",
                securityPrimitive: "strong-password-hash",
                rationale: "Fast hash algorithms enable offline brute-force attacks against stolen credential databases.",
            },
        ],
    },
    {
        id: "CWE-613",
        name: "Insufficient Session Expiration",
        description: "The product does not sufficiently expire session tokens",
        owaspCategory: "A07:2021-Identification and Authentication Failures",
        severity: "medium",
        tags: ["authentication", "session", "expiration"],
        triggerConditions: [
            {
                id: "TC-613-1",
                description: "Requirement manages user sessions or tokens",
                keywords: ["session", "token", "jwt", "cookie", "login session", "signed in"],
                semanticPatterns: [
                    "maintain.*session",
                    "issue.*token",
                    "keep.*user.*signed in",
                    "session.*management",
                ],
            },
        ],
        earsConstraints: [
            {
                id: "EC-613-1",
                pattern: "ubiquitous",
                template: "THE SYSTEM SHALL enforce a maximum session duration of {configured_limit} and SHALL invalidate the session server-side upon expiration or explicit logout.",
                securityPrimitive: "session-expiration",
                rationale: "Unbounded sessions allow indefinite access from stolen credentials or abandoned sessions.",
            },
        ],
    },
    {
        id: "CWE-384",
        name: "Session Fixation",
        description: "The product does not create a new session upon authentication, allowing session fixation attacks",
        owaspCategory: "A07:2021-Identification and Authentication Failures",
        severity: "high",
        tags: ["authentication", "session", "fixation"],
        triggerConditions: [
            {
                id: "TC-384-1",
                description: "Requirement involves authentication that establishes a session",
                keywords: ["login", "authenticate", "sign in", "session", "establish session"],
                semanticPatterns: [
                    "user.*authenticate",
                    "establish.*session.*after.*login",
                    "create.*session",
                ],
            },
        ],
        earsConstraints: [
            {
                id: "EC-384-1",
                pattern: "event-driven",
                template: "WHEN a user authenticates successfully, THE SYSTEM SHALL invalidate any pre-existing session identifier AND SHALL issue a new session identifier.",
                securityPrimitive: "session-regeneration",
                rationale: "Session regeneration on authentication prevents attackers from pre-setting session tokens.",
            },
        ],
    },
];
//# sourceMappingURL=authentication.js.map