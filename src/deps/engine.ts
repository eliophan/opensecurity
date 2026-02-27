import type { DependencyFinding } from "./types.js";
import type { CveLookupOptions } from "./cve.js";
import { scanDependencies } from "./scanners.js";
import { createCveLookup } from "./cve.js";
import { scoreRisk } from "./scoring.js";
import { buildPatchSuggestion } from "./patch.js";
import { buildSimulation } from "./simulate.js";

export type DependencyScanOptions = {
  cwd: string;
  cveLookup: CveLookupOptions;
  simulate?: boolean;
  dataSensitivity?: "low" | "medium" | "high";
};

export async function scanDependenciesWithCves(
  options: DependencyScanOptions
): Promise<DependencyFinding[]> {
  const deps = await scanDependencies(options.cwd);
  const lookup = createCveLookup(options.cveLookup, options.cwd);
  const findings: DependencyFinding[] = [];

  for (const dep of deps) {
    const cves = await lookup.lookup(dep);
    for (const cve of cves) {
      const risk = scoreRisk(cve, { dataSensitivity: options.dataSensitivity });
      const finding: DependencyFinding = {
        dependency: dep,
        cve,
        risk,
        recommendation: buildPatchSuggestion({ dependency: dep, cve, risk })
      };
      if (options.simulate) {
        finding.simulation = buildSimulation({ dependency: dep, cve, risk });
      }
      findings.push(finding);
    }
  }

  return findings;
}
