import { describe, it, expect } from "vitest";
import { runInfraPatterns } from "../src/analysis/infraPatterns.js";

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
});
