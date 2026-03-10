import { describe, it, expect } from "vitest";
import type { LanguageConfig } from "../src/native/languages.js";
import type { NativeRuleSet } from "../src/native/rules.js";
import { runNativeTaint } from "../src/native/taint.js";

type Node = {
  type: string;
  startIndex: number;
  endIndex: number;
  startPosition?: { row: number; column: number };
  namedChildren?: Node[];
  childForFieldName?: (name: string) => Node | null;
};

function node(
  type: string,
  start: number,
  end: number,
  fields: Record<string, Node | null> = {},
  children: Node[] = []
): Node {
  return {
    type,
    startIndex: start,
    endIndex: end,
    startPosition: { row: 0, column: start },
    namedChildren: children,
    childForFieldName: (name) => fields[name] ?? null
  };
}

describe("native taint engine", () => {
  it("propagates taint from source to sink", () => {
    const source = "input();\nexec(cmd);";
    const identifier = node("identifier", 0, 5);
    const sourceCall = node("call", 0, 7, { function: identifier, arguments: node("arguments", 6, 7, {}, []) });
    const assignLeft = node("identifier", 9, 12);
    const assign = node("assignment", 9, 15, { left: assignLeft, right: sourceCall });
    const sinkName = node("identifier", 16, 20);
    const sinkArg = node("identifier", 21, 24);
    const sinkCall = node("call", 16, 25, { function: sinkName, arguments: node("arguments", 20, 25, {}, [sinkArg]) }, [sinkArg]);
    const root = node("root", 0, 25, {}, [assign, sinkCall]);

    const lang: LanguageConfig = {
      id: "python",
      name: "TestLang",
      extensions: [".t"],
      wasmFile: "test.wasm",
      nativeModule: "test",
      callNodes: ["call"],
      callCalleeFields: ["function"],
      callArgumentFields: ["arguments"],
      assignmentNodes: ["assignment"],
      assignmentLeftFields: ["left"],
      assignmentRightFields: ["right"],
      memberNodes: [],
      memberObjectFields: [],
      memberPropertyFields: [],
      identifierNodes: ["identifier"],
      stringNodes: ["string"]
    };

    const rules: NativeRuleSet = {
      language: "python",
      rules: [
        {
          id: "test-taint",
          title: "Test Taint",
          severity: "high",
          owasp: "A03:2021 Injection",
          kind: "taint",
          sources: [{ id: "src", name: "input", matcher: { callee: ["input"] } }],
          sinks: [{ id: "sink", name: "exec", matcher: { callee: ["exec"] } }],
          sanitizers: []
        }
      ]
    };

    const findings = runNativeTaint({ rootNode: root }, source, lang, rules, "sample.t");
    expect(findings.length).toBe(1);
    expect(findings[0]?.ruleId).toBe("test-taint");
  });
});
