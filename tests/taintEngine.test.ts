import { describe, it, expect } from "vitest";
import { parseSource } from "../src/analysis/ast.js";
import { runTaintAnalysis } from "../src/analysis/taint.js";

const RULES = {
  sources: [{ id: "src-user", name: "getUserInput", matcher: { callee: "getUserInput" } }],
  sinks: [{ id: "sink-eval", name: "eval", matcher: { callee: "eval" } }],
  sanitizers: [{ id: "san-sanitize", name: "sanitize", matcher: { callee: "sanitize" } }]
};

describe("taint analysis", () => {
  it("flags tainted flow from source to sink", () => {
    const code = `
      const input = getUserInput();
      eval(input);
    `;
    const parsed = parseSource(code, "test.ts");
    const findings = runTaintAnalysis(parsed.ast, parsed.filePath, RULES);
    expect(findings.length).toBe(1);
    expect(findings[0].sinkId).toBe("sink-eval");
  });

  it("does not flag sanitized flow", () => {
    const code = `
      const input = getUserInput();
      const safe = sanitize(input);
      eval(safe);
    `;
    const parsed = parseSource(code, "test.ts");
    const findings = runTaintAnalysis(parsed.ast, parsed.filePath, RULES);
    expect(findings.length).toBe(0);
  });

  it("propagates taint through assignment", () => {
    const code = `
      let x = getUserInput();
      const y = x;
      eval(y);
    `;
    const parsed = parseSource(code, "test.ts");
    const findings = runTaintAnalysis(parsed.ast, parsed.filePath, RULES);
    expect(findings.length).toBe(1);
  });
});
