import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { runNativeTaint } from "../src/engines/native/taint.js";
import { loadNativeRules } from "../src/engines/native/rules.js";
import type { LanguageConfig } from "../src/engines/native/languages.js";

type FakeNode = {
  type: string;
  startIndex: number;
  endIndex: number;
  startPosition?: { row: number; column: number };
  namedChildren?: FakeNode[];
  childForFieldName?: (name: string) => FakeNode | null;
};

function node(
  type: string,
  start: number,
  end: number,
  fields: Record<string, FakeNode | null> = {},
  children: FakeNode[] = []
): FakeNode {
  return {
    type,
    startIndex: start,
    endIndex: end,
    startPosition: { row: 0, column: start },
    namedChildren: children,
    childForFieldName: (name) => fields[name] ?? null
  };
}

function buildSimpleTree(lang: LanguageConfig, source: string, sourceCallee: string, sinkCallee: string): FakeNode {
  const srcStart = source.indexOf(sourceCallee);
  const sinkStart = source.indexOf(sinkCallee);
  if (srcStart < 0 || sinkStart < 0) {
    throw new Error(`fixture missing callee: ${sourceCallee} or ${sinkCallee}`);
  }
  const srcIdent = node("identifier", srcStart, srcStart + sourceCallee.length);
  const srcCall = node(
    lang.callNodes[0] ?? "call",
    srcStart,
    srcStart + `${sourceCallee}()`.length,
    { [lang.callCalleeFields[0] ?? "function"]: srcIdent },
    [srcIdent]
  );

  const leftIdent = node("identifier", 0, 1);
  const assign = node(
    lang.assignmentNodes[0] ?? "assignment",
    0,
    srcCall.endIndex,
    { [lang.assignmentLeftFields[0] ?? "left"]: leftIdent, [lang.assignmentRightFields[0] ?? "right"]: srcCall },
    [leftIdent, srcCall]
  );

  const sinkIdent = node("identifier", sinkStart, sinkStart + sinkCallee.length);
  const argIdent = node("identifier", sinkStart + sinkCallee.length + 1, sinkStart + sinkCallee.length + 2);
  const sinkCall = node(
    lang.callNodes[0] ?? "call",
    sinkStart,
    sinkStart + sinkCallee.length + 3,
    { [lang.callCalleeFields[0] ?? "function"]: sinkIdent },
    [argIdent]
  );

  return node("root", 0, source.length, {}, [assign, sinkCall]);
}

const FIXTURE_SOURCES: Record<string, { source: string; sourceCallee: string; sinkCallee: string }> = {
  python: { source: "x = request.args.get()\nos.system(x)", sourceCallee: "request.args.get", sinkCallee: "os.system" },
  go: { source: "x = r.FormValue()\nexec.Command(x)", sourceCallee: "r.FormValue", sinkCallee: "exec.Command" },
  java: { source: "x = request.getParameter()\nRuntime.getRuntime.exec(x)", sourceCallee: "request.getParameter", sinkCallee: "Runtime.getRuntime.exec" },
  csharp: { source: "x = Request.QueryString()\nProcess.Start(x)", sourceCallee: "Request.QueryString", sinkCallee: "Process.Start" },
  ruby: { source: "x = params.id()\nsystem(x)", sourceCallee: "params.id", sinkCallee: "system" },
  php: { source: "x = $_GET()\nexec(x)", sourceCallee: "$_GET", sinkCallee: "exec" },
  rust: { source: "x = Query::id()\nCommand::new(x)", sourceCallee: "Query::id", sinkCallee: "Command::new" },
  kotlin: { source: "x = request.getParameter()\nRuntime.getRuntime.exec(x)", sourceCallee: "request.getParameter", sinkCallee: "Runtime.getRuntime.exec" },
  swift: { source: "x = request.query()\nProcess.run(x)", sourceCallee: "request.query", sinkCallee: "Process.run" },
  c: { source: "x = getenv()\nsystem(x)", sourceCallee: "getenv", sinkCallee: "system" },
  cpp: { source: "x = getenv()\nsystem(x)", sourceCallee: "getenv", sinkCallee: "system" }
};

describe("native taint smoke", () => {
  it("produces at least one finding per language", () => {
    const rulesDir = path.resolve("rules/taint");
    const ruleFiles = fs.readdirSync(rulesDir).filter((file) => file.endsWith(".json"));
    expect(ruleFiles.length).toBeGreaterThan(0);

    for (const file of ruleFiles) {
      const ruleSet = loadNativeRules(path.join(rulesDir, file));
      const langId = ruleSet.language;
      const fixture = FIXTURE_SOURCES[langId];
      expect(fixture, `missing fixture for ${langId}`).toBeTruthy();
      const lang: LanguageConfig = {
        id: langId,
        name: langId,
        extensions: [".t"],
        wasmFile: "test.wasm",
        nativeModule: "test",
        callNodes: ["call"],
        functionNodes: ["function"],
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

      const tree = buildSimpleTree(lang, fixture.source, fixture.sourceCallee, fixture.sinkCallee);
      const findings = runNativeTaint({ rootNode: tree }, fixture.source, lang, ruleSet, "sample.t");
      expect(findings.length).toBeGreaterThan(0);
    }
  });
});
