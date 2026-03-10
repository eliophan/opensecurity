import { describe, it, expect } from "vitest";
import { parseSource } from "../src/engines/analysis/ast.js";
import { runRuleEngine, mapFindingsToOwasp } from "../src/engines/analysis/rules.js";

const RULES = [
  {
    id: "rule-injection",
    name: "Eval Injection",
    description: "Untrusted data reaches eval",
    severity: "high",
    owasp: "A03:2021 Injection",
    sources: [{ id: "src-user", name: "getUserInput", matcher: { callee: "getUserInput" } }],
    sinks: [{ id: "sink-eval", name: "eval", matcher: { callee: "eval" } }],
    sanitizers: [{ id: "san-sanitize", name: "sanitize", matcher: { callee: "sanitize" } }]
  }
] as const;

describe("rule engine", () => {
  it("maps findings to OWASP category", () => {
    const code = `
      const input = getUserInput();
      eval(input);
    `;
    const parsed = parseSource(code, "test.ts");
    const findings = runRuleEngine(parsed.ast, parsed.filePath, [...RULES]);
    expect(findings.length).toBe(1);
    expect(findings[0].owasp).toBe("A03:2021 Injection");

    const map = mapFindingsToOwasp(findings);
    const bucket = map.get("A03:2021 Injection");
    expect(bucket?.length).toBe(1);
  });
});
