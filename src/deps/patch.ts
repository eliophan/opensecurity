import type { DependencyFinding } from "./types.js";

export function buildPatchSuggestion(finding: DependencyFinding): string {
  const dep = finding.dependency;
  const cve = finding.cve;
  if (cve.fixedVersion) {
    return `Upgrade ${dep.name} to ${cve.fixedVersion} or later.`;
  }
  if (cve.affectedRange) {
    return `Avoid versions in range ${cve.affectedRange}.`;
  }
  return `Review ${dep.name} usage and upgrade to a patched version.`;
}
