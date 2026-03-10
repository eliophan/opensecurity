import { describe, it, expect } from "vitest";
import type { LanguageConfig } from "../src/engines/native/languages.js";
import type { NativeRuleSet } from "../src/engines/native/rules.js";
import { runNativeTaint } from "../src/engines/native/taint.js";

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
    const source = "cmd = input();\nexec(cmd);";
    const inputIdent = node("identifier", 6, 11);
    const sourceCall = node("call", 6, 13, { function: inputIdent, arguments: node("arguments", 11, 13, {}, []) });
    const assignLeft = node("identifier", 0, 3);
    const assign = node("assignment", 0, 13, { left: assignLeft, right: sourceCall });
    const sinkName = node("identifier", 15, 19);
    const sinkArg = node("identifier", 20, 23);
    const sinkCall = node("call", 15, 24, { function: sinkName, arguments: node("arguments", 19, 24, {}, [sinkArg]) }, [sinkArg]);
    const root = node("root", 0, 24, {}, [assign, sinkCall]);

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
