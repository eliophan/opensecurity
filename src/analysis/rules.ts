import type { File } from "@babel/types";
import { runTaintAnalysis, type TaintEndpoint, type TaintFinding } from "./taint.js";

export type OwaspCategory =
  | "A01:2021 Broken Access Control"
  | "A02:2021 Cryptographic Failures"
  | "A03:2021 Injection"
  | "A04:2021 Insecure Design"
  | "A05:2021 Security Misconfiguration"
  | "A06:2021 Vulnerable and Outdated Components"
  | "A07:2021 Identification and Authentication Failures"
  | "A08:2021 Software and Data Integrity Failures"
  | "A09:2021 Security Logging and Monitoring Failures"
  | "A10:2021 Server-Side Request Forgery";

export type RuleSeverity = "low" | "medium" | "high" | "critical";

export type OwaspRule = {
  id: string;
  name: string;
  description: string;
  severity: RuleSeverity;
  owasp: OwaspCategory;
  sources: TaintEndpoint[];
  sinks: TaintEndpoint[];
  sanitizers: TaintEndpoint[];
};

export type RuleFinding = {
  ruleId: string;
  ruleName: string;
  owasp: OwaspCategory;
  severity: RuleSeverity;
  file: string;
  line?: number;
  message: string;
};

export const OWASP_TOP_10: OwaspCategory[] = [
  "A01:2021 Broken Access Control",
  "A02:2021 Cryptographic Failures",
  "A03:2021 Injection",
  "A04:2021 Insecure Design",
  "A05:2021 Security Misconfiguration",
  "A06:2021 Vulnerable and Outdated Components",
  "A07:2021 Identification and Authentication Failures",
  "A08:2021 Software and Data Integrity Failures",
  "A09:2021 Security Logging and Monitoring Failures",
  "A10:2021 Server-Side Request Forgery"
];

export function runRuleEngine(ast: File, filePath: string, rules: OwaspRule[]): RuleFinding[] {
  const findings: RuleFinding[] = [];

  for (const rule of rules) {
    const taintFindings: TaintFinding[] = runTaintAnalysis(ast, filePath, {
      sources: rule.sources,
      sinks: rule.sinks,
      sanitizers: rule.sanitizers
    });

    for (const finding of taintFindings) {
      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        owasp: rule.owasp,
        severity: rule.severity,
        file: filePath,
        line: finding.line,
        message: `${rule.name}: ${finding.message}`
      });
    }
  }

  return findings;
}

export function mapFindingsToOwasp(findings: RuleFinding[]): Map<OwaspCategory, RuleFinding[]> {
  const map = new Map<OwaspCategory, RuleFinding[]>();
  for (const category of OWASP_TOP_10) {
    map.set(category, []);
  }

  for (const finding of findings) {
    const bucket = map.get(finding.owasp);
    if (bucket) bucket.push(finding);
  }

  return map;
}
