import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";

type RuleFile = {
  language: string;
  rules: Array<{ title: string }>;
};

const REQUIRED_BY_LANGUAGE: Record<string, string[]> = {
  python: [
    "SQL Injection",
    "Command Injection",
    "Path Traversal",
    "Server-Side Request Forgery",
    "Unsafe Deserialization",
    "Server Template XSS",
    "Weak Crypto",
    "Hardcoded Secret"
  ],
  go: [
    "SQL Injection",
    "Command Injection",
    "Path Traversal",
    "Server-Side Request Forgery",
    "Server Template XSS",
    "Weak Crypto",
    "Hardcoded Secret"
  ],
  java: [
    "SQL Injection",
    "Command Injection",
    "Path Traversal",
    "Server-Side Request Forgery",
    "Unsafe Deserialization",
    "Server Template XSS",
    "Weak Crypto",
    "Hardcoded Secret"
  ],
  csharp: [
    "SQL Injection",
    "Command Injection",
    "Path Traversal",
    "Server-Side Request Forgery",
    "Unsafe Deserialization",
    "Server Template XSS",
    "Weak Crypto",
    "Hardcoded Secret"
  ],
  ruby: [
    "SQL Injection",
    "Command Injection",
    "Path Traversal",
    "Server-Side Request Forgery",
    "Unsafe Deserialization",
    "Server Template XSS",
    "Weak Crypto",
    "Hardcoded Secret"
  ],
  php: [
    "SQL Injection",
    "Command Injection",
    "Path Traversal",
    "Server-Side Request Forgery",
    "Unsafe Deserialization",
    "Server Template XSS",
    "Weak Crypto",
    "Hardcoded Secret"
  ],
  rust: [
    "SQL Injection",
    "Command Injection",
    "Path Traversal",
    "Server-Side Request Forgery",
    "Server Template XSS",
    "Weak Crypto",
    "Hardcoded Secret"
  ],
  kotlin: [
    "SQL Injection",
    "Command Injection",
    "Path Traversal",
    "Server-Side Request Forgery",
    "Server Template XSS",
    "Weak Crypto",
    "Hardcoded Secret"
  ],
  swift: [
    "SQL Injection",
    "Command Injection",
    "Path Traversal",
    "Server-Side Request Forgery",
    "Server Template XSS",
    "Weak Crypto",
    "Hardcoded Secret"
  ],
  c: ["Command Injection", "Path Traversal", "Weak Crypto", "Hardcoded Secret"],
  cpp: ["Command Injection", "Path Traversal", "Weak Crypto", "Hardcoded Secret"]
};

function loadRuleFile(filePath: string): RuleFile {
  return JSON.parse(fs.readFileSync(filePath, "utf8")) as RuleFile;
}

describe("taint rule coverage", () => {
  it("matches expected coverage per language", () => {
    const dir = path.resolve("rules/taint");
    const files = fs.readdirSync(dir).filter((file) => file.endsWith(".json"));
    expect(files.length).toBeGreaterThan(0);

    for (const file of files) {
      const data = loadRuleFile(path.join(dir, file));
      const expected = REQUIRED_BY_LANGUAGE[data.language];
      expect(expected, `missing coverage definition for ${data.language}`).toBeTruthy();
      const titles = new Set(data.rules.map((rule) => rule.title));
      for (const title of expected) {
        expect(titles.has(title)).toBe(true);
      }
    }
  });
});
