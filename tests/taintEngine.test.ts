import { describe, it, expect } from "vitest";
import { parseSource } from "../src/engines/analysis/ast.js";
import { runTaintAnalysis } from "../src/engines/analysis/taint.js";

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

  it("matches deep member access and suffix names", () => {
    const code = `
      const input = request.args.get("id");
      db.execute(input);
    `;
    const parsed = parseSource(code, "test.ts");
    const rules = {
      sources: [{ id: "src", name: "request.args.get", matcher: { callee: "request.args.get" } }],
      sinks: [{ id: "sink", name: "execute", matcher: { callee: "execute" } }],
      sanitizers: []
    };
    const findings = runTaintAnalysis(parsed.ast, parsed.filePath, rules);
    expect(findings.length).toBe(1);
  });
});
