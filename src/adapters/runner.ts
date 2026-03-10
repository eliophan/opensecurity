import path from "node:path";
import type { Finding } from "../scan.js";
import type { Adapter } from "./types.js";
import { banditAdapter } from "./bandit.js";
import { brakemanAdapter } from "./brakeman.js";
import { gosecAdapter } from "./gosec.js";
import { semgrepAdapter } from "./semgrep.js";

export type AdapterRunResult = {
  findings: Finding[];
  warnings: string[];
};

export const ALL_ADAPTERS: Adapter[] = [
  banditAdapter,
  gosecAdapter,
  brakemanAdapter,
  semgrepAdapter
];

export function filterAdapters(allowList?: string[]): Adapter[] {
  if (!allowList || allowList.length === 0) return [...ALL_ADAPTERS];
  const normalized = new Set(allowList.map((item) => item.trim().toLowerCase()).filter(Boolean));
  return ALL_ADAPTERS.filter((adapter) => normalized.has(adapter.id));
}

export async function runExternalAdapters(options: {
  cwd: string;
  files: string[];
  allowList?: string[];
}): Promise<AdapterRunResult> {
  const selected = filterAdapters(options.allowList);
  const warnings: string[] = [];
  const findings: Finding[] = [];

  for (const adapter of selected) {
    const matching = options.files.filter((filePath) => adapter.matchFile(filePath));
    if (!matching.length) continue;
    const available = await adapter.isAvailable();
    if (!available) {
      warnings.push(`Adapter "${adapter.id}" skipped: ${adapter.name} not found in PATH.`);
      continue;
    }
    const relPaths = matching.map((filePath) => path.relative(options.cwd, filePath).split(path.sep).join("/"));
    try {
      const adapterFindings = await adapter.run({
        cwd: options.cwd,
        targetPaths: matching,
        relPaths,
        onWarning: (message) => warnings.push(message)
      });
      findings.push(...adapterFindings);
    } catch (err: any) {
      warnings.push(`Adapter "${adapter.id}" failed: ${err?.message ?? err}`);
    }
  }

  return { findings, warnings };
}
