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
    pattern: /\bUSER\s+root\b/i
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
    id: "k8s-host-ipc",
    title: "Host IPC Enabled",
    description: "Kubernetes manifest enables hostIPC which reduces isolation.",
    severity: "medium",
    owasp: "A05:2021 Security Misconfiguration",
    pattern: /\bhostIPC\s*:\s*true\b/i
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
    id: "k8s-allow-priv-esc",
    title: "Privilege Escalation Enabled",
    description: "Kubernetes manifest allows privilege escalation.",
    severity: "high",
    owasp: "A05:2021 Security Misconfiguration",
    pattern: /\ballowPrivilegeEscalation\s*:\s*true\b/i
  },
  {
    id: "k8s-no-readonly-fs",
    title: "Writable Root Filesystem",
    description: "Kubernetes manifest allows writable root filesystem.",
    severity: "medium",
    owasp: "A05:2021 Security Misconfiguration",
    pattern: /\breadOnlyRootFilesystem\s*:\s*false\b/i
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
    id: "k8s-run-as-user-root",
    title: "Container Runs as Root UID",
    description: "Kubernetes manifest sets runAsUser to 0 (root).",
    severity: "medium",
    owasp: "A05:2021 Security Misconfiguration",
    pattern: /\brunAsUser\s*:\s*0\b/i
  },
  {
    id: "k8s-seccomp-unconfined",
    title: "Seccomp Unconfined",
    description: "Kubernetes manifest disables seccomp confinement.",
    severity: "high",
    owasp: "A05:2021 Security Misconfiguration",
    pattern: /\bseccompProfile\b[\s\S]*?\btype\s*:\s*Unconfined\b/i
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
    id: "terraform-open-sg-port",
    title: "Open Security Group Port",
    description: "Terraform security group allows public ingress on common ports.",
    severity: "high",
    owasp: "A05:2021 Security Misconfiguration",
    pattern: /\b(from_port|to_port)\s*=\s*(22|3389|5432|3306|6379|9200|27017)\b[\s\S]*0\.0\.0\.0\/0/i
  },
  {
    id: "terraform-public-s3-acl",
    title: "Public S3 ACL",
    description: "Terraform S3 ACL is public-read or public-read-write.",
    severity: "high",
    owasp: "A05:2021 Security Misconfiguration",
    pattern: /\bacl\s*=\s*\"public-read(-write)?\"/i
  },
  {
    id: "terraform-s3-public-block-disabled",
    title: "S3 Public Access Block Disabled",
    description: "Terraform disables S3 public access block.",
    severity: "high",
    owasp: "A05:2021 Security Misconfiguration",
    pattern: /\b(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false\b/i
  },
  {
    id: "terraform-rds-public",
    title: "Public RDS Instance",
    description: "Terraform RDS instance is publicly accessible.",
    severity: "high",
    owasp: "A05:2021 Security Misconfiguration",
    pattern: /\bpublicly_accessible\s*=\s*true\b/i
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
  const lineStarts: number[] = [0];
  for (let i = 0; i < content.length; i += 1) {
    if (content[i] === "\n") lineStarts.push(i + 1);
  }

  const findLine = (index: number) => {
    let low = 0;
    let high = lineStarts.length - 1;
    while (low <= high) {
      const mid = Math.floor((low + high) / 2);
      if (lineStarts[mid] <= index) {
        if (mid === lineStarts.length - 1 || lineStarts[mid + 1] > index) return mid + 1;
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    return 1;
  };

  for (const rule of RULES) {
    const flags = rule.pattern.flags.includes("g") ? rule.pattern.flags : `${rule.pattern.flags}g`;
    const regex = new RegExp(rule.pattern.source, flags);
    let match: RegExpExecArray | null;
    while ((match = regex.exec(content)) !== null) {
      const line = findLine(match.index);
      findings.push({
        id: rule.id,
        severity: rule.severity,
        owasp: rule.owasp,
        title: rule.title,
        description: rule.description,
        file: filePath,
        line
      });
    }
  }
  return findings;
}
