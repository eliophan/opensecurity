import type { RuleSeverity } from "../analysis/rules.js";

export type Ecosystem = "npm" | "pypi";
export type DependencyScope = "prod" | "dev";

export type Dependency = {
  name: string;
  version?: string;
  spec?: string;
  ecosystem: Ecosystem;
  scope: DependencyScope;
  source: string;
};

export type CveRecord = {
  id: string;
  package: string;
  ecosystem?: Ecosystem;
  affectedRange?: string;
  fixedVersion?: string;
  severity?: RuleSeverity;
  cvssScore?: number;
  description?: string;
  references?: string[];
  exploitability?: "low" | "medium" | "high";
  privilegeRequired?: "none" | "low" | "high";
};

export type RiskScore = {
  score: number;
  severity: RuleSeverity;
  factors: {
    base: number;
    exploitability: number;
    privilegeRequired: number;
    dataSensitivity: number;
  };
};

export type DependencyFinding = {
  dependency: Dependency;
  cve: CveRecord;
  risk: RiskScore;
  recommendation?: string;
  simulation?: { payload: string; impact: string };
};
