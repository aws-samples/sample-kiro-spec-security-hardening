# Spec It Safe (SIS) — Security Hardening for Spec-Driven Development

## Purpose

This subagent hardens EARS-format requirements with security constraints derived from CWE/CVE/OWASP mappings. It ensures that security is a native, first-class construct in the specification — not an afterthought bolted on at code review.

## When to Invoke

Invoke this subagent **after** all functional requirements are finalized in EARS format and **before** code generation begins. The workflow is:

```
Specify → [SIS Hardening] → Plan → Execute
```

## Invocation

### As a library (programmatic)

```typescript
import { HardeningEngine, formatAsSecurityAnnotatedEARS } from "@sis/cwe-to-spec-mapping";

const engine = new HardeningEngine();
const report = engine.harden(requirements);
const hardenedSpec = formatAsSecurityAnnotatedEARS(report);
```

### As a CLI (stdin/file)

```bash
echo '{"requirements": [...]}' | npx tsx .kiro/harden.ts
# or
npx tsx .kiro/harden.ts requirements.json
```

### Input Schema

```json
{
  "requirements": [
    {
      "id": "REQ-1",
      "text": "WHEN a user submits a search query, THE SYSTEM SHALL return matching results from the database.",
      "earsPattern": "event-driven",
      "securityAnnotations": []
    }
  ],
  "options": {
    "confidenceThreshold": 0.3,
    "includeLowSeverity": true,
    "maxProposalsPerRequirement": 10
  }
}
```

### Output Schema

The output contains:
- `hardenedSpec`: A formatted string with the original requirements plus security annotations
- `report`: The full `HardeningReport` object with per-requirement details, triggered CWEs, proposals, and summary scores

## Integration with Kiro Workflows

In a Kiro spec-driven workflow, this subagent sits between the requirements authoring phase and the implementation planning phase. It reads the `.kiro/specs/*.md` files containing EARS requirements, parses them, runs the hardening engine, and writes back the hardened specifications.

The agent follows these principles:
1. **Contextual** — only adds security constraints semantically relevant to each requirement
2. **Additive** — never removes or weakens functional requirements
3. **Explicit** — security invariants are stated in the spec, not assumed from middleware
4. **Traceable** — every constraint maps to a specific CWE with rationale
