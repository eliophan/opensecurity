import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";

type RuleFile = {
  language: string;
  rules: Array<{ title: string }>;
};

type Fixtures = Record<string, Record<string, string[]>>;

function loadJson<T>(filePath: string): T {
  return JSON.parse(fs.readFileSync(filePath, "utf8")) as T;
}

describe("taint rule fixtures", () => {
  it("provides at least one fixture per rule title", () => {
    const rulesDir = path.resolve("rules/taint");
    const fixturesPath = path.resolve("tests/fixtures/taint-fixtures.json");
    const fixtures = loadJson<Fixtures>(fixturesPath);
    const files = fs.readdirSync(rulesDir).filter((file) => file.endsWith(".json"));

    expect(files.length).toBeGreaterThan(0);

    for (const file of files) {
      const ruleFile = loadJson<RuleFile>(path.join(rulesDir, file));
      const perLang = fixtures[ruleFile.language];
      expect(perLang, `missing fixtures for ${ruleFile.language}`).toBeTruthy();
      for (const rule of ruleFile.rules) {
        const samples = perLang[rule.title];
        expect(samples, `missing fixture for ${ruleFile.language}:${rule.title}`).toBeTruthy();
        expect(samples.length).toBeGreaterThan(0);
      }
    }
  });
});
