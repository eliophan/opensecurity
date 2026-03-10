import type { OwaspCategory, RuleSeverity } from "./rules.js";

export type InfraFinding = {
  id: string;
  severity: RuleSeverity;
  owasp: OwaspCategory;
  title: string;
  description: string;
  file: string;
  line?: number;
};

type InfraRule = {
  id: string;
  title: string;
  description: string;
  severity: RuleSeverity;
  owasp: OwaspCategory;
  pattern: RegExp;
};

const RULES: InfraRule[] = [
  {
    id: "dockerfile-root-user",
    title: "Container Runs as Root",
    description: "Dockerfile runs as root user; consider using a non-root user.",
    severity: "medium",
    owasp: "A05:2021 Security Misconfiguration",
    pattern: /^\s*USER\s+root\b/i
  },
  {
    id: "dockerfile-privileged",
    title: "Privileged Container",
    description: "Dockerfile enables privileged mode or sets all capabilities.",
    severity: "high",
    owasp: "A05:2021 Security Misconfiguration",
    pattern: /\b(--privileged|CAP_SYS_ADMIN|cap_add\s*:\s*\[?\s*ALL\s*\]?)/i
  },
  {
    id: "k8s-privileged",
    title: "Privileged Kubernetes Pod",
    description: "Kubernetes manifest enables privileged containers.",
    severity: "high",
    owasp: "A05:2021 Security Misconfiguration",
    pattern: /\bprivileged\s*:\s*true\b/i
  },
  {
    id: "k8s-host-path",
    title: "HostPath Volume",
    description: "Kubernetes HostPath volume may allow host access.",
    severity: "medium",
    owasp: "A05:2021 Security Misconfiguration",
    pattern: /\bhostPath\s*:\b/i
  },
  {
    id: "k8s-host-network",
    title: "Host Network Enabled",
    description: "Kubernetes manifest enables hostNetwork which reduces isolation.",
    severity: "medium",
    owasp: "A05:2021 Security Misconfiguration",
    pattern: /\bhostNetwork\s*:\s*true\b/i
  },
  {
    id: "k8s-host-pid",
    title: "Host PID Namespace",
    description: "Kubernetes manifest enables hostPID which reduces isolation.",
    severity: "medium",
    owasp: "A05:2021 Security Misconfiguration",
    pattern: /\bhostPID\s*:\s*true\b/i
  },
  {
    id: "k8s-run-as-root",
    title: "Container Runs as Root",
    description: "Kubernetes securityContext allows root user.",
    severity: "medium",
    owasp: "A05:2021 Security Misconfiguration",
    pattern: /\brunAsNonRoot\s*:\s*false\b/i
  },
  {
    id: "terraform-public-sg",
    title: "Public Security Group",
    description: "Terraform security group allows ingress from all sources.",
    severity: "high",
    owasp: "A05:2021 Security Misconfiguration",
    pattern: /\b(cidr_blocks|cidr_block)\s*=\s*\[?\s*\"0\.0\.0\.0\/0\"\s*\]?/i
  },
  {
    id: "terraform-public-acl",
    title: "Public Network ACL",
    description: "Terraform network ACL allows ingress from all sources.",
    severity: "high",
    owasp: "A05:2021 Security Misconfiguration",
    pattern: /\b(ingress|egress)\b[\s\S]*0\.0\.0\.0\/0/i
  },
  {
    id: "yaml-insecure-tls",
    title: "Insecure TLS",
    description: "Config disables TLS verification.",
    severity: "medium",
    owasp: "A02:2021 Cryptographic Failures",
    pattern: /\b(insecureSkipVerify|ssl_verify\s*:\s*false|verify_ssl\s*:\s*false)\b/i
  }
];

export function runInfraPatterns(content: string, filePath: string): InfraFinding[] {
  const findings: InfraFinding[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    for (const rule of RULES) {
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
