import type { OwaspCategory, RuleSeverity } from "./rules.js";

export type UniversalFinding = {
  id: string;
  severity: RuleSeverity;
  owasp: OwaspCategory;
  title: string;
  description: string;
  file: string;
  line?: number;
};

type PatternRule = {
  id: string;
  title: string;
  description: string;
  severity: RuleSeverity;
  owasp: OwaspCategory;
  pattern: RegExp;
};

const PATTERNS: PatternRule[] = [
  {
    id: "exec-os-system",
    title: "Command Execution",
    description: "Potential command execution via system call.",
    severity: "critical",
    owasp: "A03:2021 Injection",
    pattern: /\b(os\.system|subprocess\.(call|run|Popen)|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|exec\.Command|system\s*\(|popen\s*\(|Process\.Start|ShellExecute)\b/gi
  },
  {
    id: "eval-exec",
    title: "Dynamic Code Execution",
    description: "Potential dynamic code execution detected.",
    severity: "high",
    owasp: "A03:2021 Injection",
    pattern: /\b(eval|exec|Function|vm\.runInThisContext|loadstring)\s*\(/gi
  },
  {
    id: "unsafe-deserialization",
    title: "Unsafe Deserialization",
    description: "Potential unsafe deserialization API usage.",
    severity: "high",
    owasp: "A08:2021 Software and Data Integrity Failures",
    pattern: /\b(pickle\.loads?|yaml\.load|YAML\.load|ObjectInputStream|BinaryFormatter|XmlSerializer|Marshal\.load|PHP\s*unserialize|unserialize\s*\()\b/gi
  },
  {
    id: "weak-crypto",
    title: "Weak Crypto",
    description: "Use of weak or deprecated crypto primitives.",
    severity: "medium",
    owasp: "A02:2021 Cryptographic Failures",
    pattern: /\b(MD5|SHA1|RC4|DES|3DES|ECB)\b/gi
  }
];

export function runUniversalPatterns(code: string, filePath: string): UniversalFinding[] {
  const findings: UniversalFinding[] = [];
  const lines = code.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    for (const rule of PATTERNS) {
      if (rule.pattern.test(line)) {
        findings.push({
          id: rule.id,
          severity: rule.severity,
          owasp: rule.owasp,
          title: rule.title,
          description: rule.description,
          file: filePath,
          line: i + 1
        });
      }
      rule.pattern.lastIndex = 0;
    }
  }
  return findings;
}
