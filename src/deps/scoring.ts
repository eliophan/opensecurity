import type { CveRecord, RiskScore } from "./types.js";

export function scoreRisk(
  cve: CveRecord,
  options: { dataSensitivity?: "low" | "medium" | "high" } = {}
): RiskScore {
  const base = baseScore(cve);
  const exploitability = cve.exploitability === "high" ? 10 : cve.exploitability === "medium" ? 5 : 0;
  const privilegeRequired = cve.privilegeRequired === "none" ? 10 : cve.privilegeRequired === "low" ? 5 : 0;
  const dataSensitivity = options.dataSensitivity === "high" ? 10 : options.dataSensitivity === "medium" ? 5 : 0;

  const score = clamp(base + exploitability + privilegeRequired + dataSensitivity, 0, 100);
  return {
    score,
    severity: scoreToSeverity(score),
    factors: {
      base,
      exploitability,
      privilegeRequired,
      dataSensitivity
    }
  };
}

function baseScore(cve: CveRecord): number {
  if (typeof cve.cvssScore === "number" && !Number.isNaN(cve.cvssScore)) {
    return clamp(cve.cvssScore * 10, 0, 100);
  }
  switch (cve.severity) {
    case "critical":
      return 90;
    case "high":
      return 70;
    case "medium":
      return 40;
    case "low":
      return 20;
    default:
      return 30;
  }
}

function scoreToSeverity(score: number): RiskScore["severity"] {
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}
