import { describe, it, expect } from "vitest";
import { runInfraPatterns } from "../src/engines/analysis/infraPatterns.js";

describe("infra patterns", () => {
  it("detects dockerfile root user", () => {
    const code = "FROM node:20\nUSER root\n";
    const findings = runInfraPatterns(code, "Dockerfile");
    expect(findings.some((f) => f.id === "dockerfile-root-user")).toBe(true);
  });

  it("detects k8s privileged", () => {
    const code = "securityContext:\n  privileged: true";
    const findings = runInfraPatterns(code, "deployment.yaml");
    expect(findings.some((f) => f.id === "k8s-privileged")).toBe(true);
  });

  it("detects terraform public sg", () => {
    const code = "cidr_blocks = [\"0.0.0.0/0\"]";
    const findings = runInfraPatterns(code, "main.tf");
    expect(findings.some((f) => f.id === "terraform-public-sg")).toBe(true);
  });

  it("detects k8s allow privilege escalation", () => {
    const code = "securityContext:\n  allowPrivilegeEscalation: true";
    const findings = runInfraPatterns(code, "deployment.yaml");
    expect(findings.some((f) => f.id === "k8s-allow-priv-esc")).toBe(true);
  });

  it("detects k8s seccomp unconfined", () => {
    const code = "securityContext:\n  seccompProfile:\n    type: Unconfined";
    const findings = runInfraPatterns(code, "deployment.yaml");
    expect(findings.some((f) => f.id === "k8s-seccomp-unconfined")).toBe(true);
  });

  it("detects terraform public s3 acl", () => {
    const code = "resource \"aws_s3_bucket\" \"b\" { acl = \"public-read\" }";
    const findings = runInfraPatterns(code, "main.tf");
    expect(findings.some((f) => f.id === "terraform-public-s3-acl")).toBe(true);
  });

  it("detects terraform public rds", () => {
    const code = "publicly_accessible = true";
    const findings = runInfraPatterns(code, "db.tf");
    expect(findings.some((f) => f.id === "terraform-rds-public")).toBe(true);
  });
});
