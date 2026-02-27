import type { DependencyFinding } from "./types.js";

export function buildSimulation(finding: DependencyFinding): { payload: string; impact: string } {
  const dep = finding.dependency;
  const cve = finding.cve;
  const payload = `Trigger ${cve.id} via ${dep.name}@${dep.version ?? dep.spec ?? "unknown"}`;
  const impact = cve.description
    ? `Potential impact: ${cve.description}`
    : `Potential impact: untrusted input could exploit ${dep.name}.`;
  return { payload, impact };
}
