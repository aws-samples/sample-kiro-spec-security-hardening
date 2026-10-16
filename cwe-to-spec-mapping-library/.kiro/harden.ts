/**
 * Kiro subagent entry point for security hardening.
 *
 * Usage: This script is invoked by the Kiro SDD workflow after requirements
 * are finalized in EARS format. It reads requirements from stdin or a file,
 * runs the hardening engine, and outputs the hardened specification.
 */

import { HardeningEngine, formatAsSecurityAnnotatedEARS } from "../src/index.js";
import type { Requirement, EARSPattern } from "../src/index.js";

interface KiroInput {
  requirements: Array<{
    id: string;
    text: string;
    earsPattern?: EARSPattern;
    securityAnnotations?: string[];
  }>;
  options?: {
    confidenceThreshold?: number;
    includeLowSeverity?: boolean;
    maxProposalsPerRequirement?: number;
  };
}

async function main() {
  const input = await readInput();
  const parsed: KiroInput = JSON.parse(input);

  const requirements: Requirement[] = parsed.requirements.map((r) => ({
    id: r.id,
    text: r.text,
    earsPattern: r.earsPattern,
    securityAnnotations: r.securityAnnotations,
  }));

  const engine = new HardeningEngine();
  const report = engine.harden(requirements, parsed.options);

  const output = {
    hardenedSpec: formatAsSecurityAnnotatedEARS(report),
    report,
  };

  process.stdout.write(JSON.stringify(output, null, 2));
}

async function readInput(): Promise<string> {
  const args = process.argv.slice(2);

  if (args[0] && args[0] !== "-") {
    const fs = await import("node:fs/promises");
    return fs.readFile(args[0], "utf-8");
  }

  return new Promise((resolve) => {
    let data = "";
    process.stdin.setEncoding("utf-8");
    process.stdin.on("data", (chunk: string) => (data += chunk));
    process.stdin.on("end", () => resolve(data));
    process.stdin.resume();
  });
}

main().catch((err) => {
  process.stderr.write(`Error: ${err.message}\n`);
  process.exit(1);
});
