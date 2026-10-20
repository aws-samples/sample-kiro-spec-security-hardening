export const cryptographyMappings = [
    {
        id: "CWE-330",
        name: "Use of Insufficiently Random Values",
        description: "The product uses insufficiently random numbers or values in a security context",
        owaspCategory: "A02:2021-Cryptographic Failures",
        severity: "high",
        tags: ["cryptography", "randomness", "token-generation"],
        triggerConditions: [
            {
                id: "TC-330-1",
                description: "Requirement involves token, session ID, or nonce generation",
                keywords: ["token", "session", "nonce", "key", "secret", "generate", "random", "uuid", "identifier"],
                semanticPatterns: [
                    "generate.*token",
                    "create.*session.*id",
                    "issue.*nonce",
                    "generate.*api.*key",
                    "create.*secret",
                    "random.*identifier",
                ],
            },
        ],
        earsConstraints: [
            {
                id: "EC-330-1",
                pattern: "ubiquitous",
                template: "THE SYSTEM SHALL generate all tokens, session identifiers, and nonces using a cryptographically secure random number generator (CSPRNG) with a minimum of 128 bits of entropy.",
                securityPrimitive: "csprng",
                rationale: "Predictable tokens enable session hijacking, CSRF bypass, and authentication replay attacks.",
            },
        ],
    },
    {
        id: "CWE-327",
        name: "Use of a Broken or Risky Cryptographic Algorithm",
        description: "The product uses a broken or risky cryptographic algorithm or protocol",
        owaspCategory: "A02:2021-Cryptographic Failures",
        severity: "high",
        tags: ["cryptography", "algorithm", "encryption"],
        triggerConditions: [
            {
                id: "TC-327-1",
                description: "Requirement involves encryption or cryptographic operations",
                keywords: ["encrypt", "decrypt", "cipher", "cryptographic", "sign", "hash", "digest"],
                semanticPatterns: [
                    "encrypt.*data",
                    "sign.*payload",
                    "hash.*value",
                    "cryptographic.*operation",
                ],
            },
        ],
        earsConstraints: [
            {
                id: "EC-327-1",
                pattern: "ubiquitous",
                template: "THE SYSTEM SHALL use only current, vetted cryptographic algorithms (AES-256-GCM for symmetric encryption, RSA-2048+ or ECDSA P-256+ for asymmetric, SHA-256+ for hashing). THE SYSTEM SHALL NOT use DES, 3DES, RC4, MD5, or SHA-1 in any security context.",
                securityPrimitive: "strong-cryptography",
                rationale: "Broken cryptographic algorithms provide a false sense of security while being trivially defeated.",
            },
        ],
    },
    {
        id: "CWE-798",
        name: "Use of Hard-coded Credentials",
        description: "The product contains hard-coded credentials such as passwords or cryptographic keys",
        owaspCategory: "A07:2021-Identification and Authentication Failures",
        severity: "critical",
        tags: ["cryptography", "credentials", "secrets-management"],
        triggerConditions: [
            {
                id: "TC-798-1",
                description: "Requirement connects to an external service or data store",
                keywords: ["connect", "integrate", "database", "service", "api", "external", "third-party", "credential"],
                semanticPatterns: [
                    "connect.*to.*database",
                    "integrate.*with.*service",
                    "call.*external.*api",
                    "authenticate.*to.*provider",
                    "access.*third.*party",
                ],
                dataFlowIndicators: ["application → external service requiring credentials"],
            },
        ],
        earsConstraints: [
            {
                id: "EC-798-1",
                pattern: "ubiquitous",
                template: "THE SYSTEM SHALL retrieve all credentials from a secrets manager or environment variable at runtime. THE SYSTEM SHALL NOT include credentials in source code, configuration files, or specification documents.",
                securityPrimitive: "secrets-management",
                rationale: "Hard-coded credentials in source are exposed through version control, CI logs, and binary inspection.",
            },
        ],
    },
    {
        id: "CWE-345",
        name: "Insufficient Verification of Data Authenticity",
        description: "The product does not verify the origin or integrity of received data",
        owaspCategory: "A08:2021-Software and Data Integrity Failures",
        severity: "high",
        tags: ["cryptography", "integrity", "signature-verification"],
        triggerConditions: [
            {
                id: "TC-345-1",
                description: "Requirement receives data from external sources that affects system state",
                keywords: ["receive", "webhook", "callback", "import", "ingest", "accept", "process external"],
                semanticPatterns: [
                    "receive.*webhook",
                    "process.*callback",
                    "ingest.*external.*data",
                    "accept.*payload.*from",
                    "import.*from.*partner",
                ],
                dataFlowIndicators: ["external source → state-changing operation"],
            },
        ],
        earsConstraints: [
            {
                id: "EC-345-1",
                pattern: "event-driven",
                template: "WHILE a payload received from an external source is being processed, THE SYSTEM SHALL verify a cryptographic signature (HMAC-SHA256 or equivalent) on the payload. THE SYSTEM SHALL reject payloads with missing or invalid signatures.",
                securityPrimitive: "payload-signature-verification",
                rationale: "Unsigned external payloads enable injection of forged events into the system.",
            },
        ],
    },
    {
        id: "CWE-326",
        name: "Inadequate Encryption Strength",
        description: "The product stores or transmits sensitive data using an encryption scheme that is insufficient for the level of protection required",
        owaspCategory: "A02:2021-Cryptographic Failures",
        severity: "medium",
        tags: ["cryptography", "encryption-strength", "key-size"],
        triggerConditions: [
            {
                id: "TC-326-1",
                description: "Requirement involves encrypting data at rest or in transit",
                keywords: ["encrypt", "protect", "secure", "store encrypted", "encrypted at rest"],
                semanticPatterns: [
                    "encrypt.*at.*rest",
                    "protect.*with.*encryption",
                    "store.*securely",
                    "encrypted.*storage",
                ],
            },
        ],
        earsConstraints: [
            {
                id: "EC-326-1",
                pattern: "ubiquitous",
                template: "THE SYSTEM SHALL encrypt sensitive data at rest using AES-256-GCM or equivalent AEAD cipher. THE SYSTEM SHALL manage encryption keys through a dedicated key management service with automatic rotation.",
                outOfScopeTerms: ["encryption", "encryption at rest"],
                securityPrimitive: "encryption-at-rest",
                rationale: "Weak encryption is computationally feasible to break, negating the protection intent.",
            },
        ],
    },
    {
        id: "CWE-295",
        name: "Improper Certificate Validation",
        description: "Failure to validate, or improper validation of, a TLS/SSL certificate",
        owaspCategory: "A07:2021-Identification and Authentication Failures",
        severity: "high",
        tags: ["cryptography", "tls", "certificate", "authentication", "transport"],
        triggerConditions: [
            {
                id: "TC-295-1",
                description: "Requirement establishes a TLS connection to an external service or endpoint",
                keywords: ["tls", "ssl", "https", "certificate", "external service", "api call", "webhook", "outbound request"],
                semanticPatterns: [
                    "connect.*over.*https",
                    "call.*external.*api",
                    "establish.*secure.*connection",
                    "trust.*endpoint",
                ],
                dataFlowIndicators: ["service → external TLS endpoint"],
            },
        ],
        earsConstraints: [
            {
                id: "EC-295-1",
                pattern: "ubiquitous",
                template: "THE SYSTEM SHALL validate the full certificate chain, hostname, and expiry of every TLS peer against a trusted certificate authority store.",
                outOfScopeTerms: ["tls", "encryption", "certificate validation"],
                securityPrimitive: "certificate-validation",
                rationale: "Skipping chain or hostname validation lets an attacker present any certificate and man-in-the-middle the connection.",
            },
            {
                id: "EC-295-2",
                pattern: "unwanted-behavior",
                template: "IF certificate validation fails for a TLS connection, THEN THE SYSTEM SHALL abort the connection and record the failure.",
                outOfScopeTerms: ["tls", "encryption", "certificate validation"],
                securityPrimitive: "fail-closed-tls",
                rationale: "Failing closed on an invalid certificate prevents silent downgrade to an untrusted channel.",
            },
        ],
    },
    {
        id: "CWE-347",
        name: "Improper Verification of Cryptographic Signature",
        description: "Failure to verify, or improper verification of, a cryptographic signature on data such as a token or assertion",
        owaspCategory: "A02:2021-Cryptographic Failures",
        severity: "high",
        tags: ["cryptography", "signature", "jwt", "saml", "authentication", "integrity"],
        triggerConditions: [
            {
                id: "TC-347-1",
                description: "Requirement parses or trusts a signed token or assertion (JWT, SAML, signed webhook)",
                keywords: ["jwt", "json web token", "saml", "signature", "assertion", "bearer token", "id token", "webhook signature"],
                semanticPatterns: [
                    "parse.*jwt",
                    "validate.*token",
                    "process.*saml.*assertion",
                    "accept.*signed.*payload",
                    "verify.*webhook",
                ],
                dataFlowIndicators: ["signed token → trusted claim"],
            },
        ],
        earsConstraints: [
            {
                id: "EC-347-1",
                pattern: "ubiquitous",
                template: "THE SYSTEM SHALL verify the cryptographic signature of every token and assertion against a server-pinned algorithm and key set.",
                securityPrimitive: "signature-verification",
                rationale: "Accepting a token without verifying its signature lets an attacker forge claims and impersonate any principal.",
            },
            {
                id: "EC-347-2",
                pattern: "unwanted-behavior",
                template: "IF a token specifies an unexpected or absent signature algorithm, THEN THE SYSTEM SHALL reject the token.",
                securityPrimitive: "algorithm-pinning",
                rationale: "Pinning the accepted algorithm blocks the 'alg: none' bypass and algorithm-confusion attacks.",
            },
        ],
    },
];
//# sourceMappingURL=cryptography.js.map