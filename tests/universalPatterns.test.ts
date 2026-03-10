import { describe, it, expect } from "vitest";
import { runUniversalPatterns } from "../src/engines/analysis/universalPatterns.js";

describe("universal patterns", () => {
  it("detects Python command execution", () => {
    const code = "import os\nos.system('ls')";
    const findings = runUniversalPatterns(code, "main.py");
    expect(findings.some((f) => f.id === "exec-os-system")).toBe(true);
  });

  it("detects Java Runtime exec", () => {
    const code = "Runtime.getRuntime().exec(cmd);";
    const findings = runUniversalPatterns(code, "Main.java");
    expect(findings.some((f) => f.id === "exec-os-system")).toBe(true);
  });

  it("detects Go exec.Command", () => {
    const code = "exec.Command(\"sh\", \"-c\", cmd)";
    const findings = runUniversalPatterns(code, "main.go");
    expect(findings.some((f) => f.id === "exec-os-system")).toBe(true);
  });

  it("detects deserialization", () => {
    const code = "pickle.loads(data)";
    const findings = runUniversalPatterns(code, "main.py");
    expect(findings.some((f) => f.id === "unsafe-deserialization")).toBe(true);
  });
});
