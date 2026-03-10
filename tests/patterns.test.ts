import { describe, it, expect } from "vitest";
import { parseSource } from "../src/analysis/ast.js";
import { runPatternDetectors } from "../src/analysis/patterns.js";

describe("pattern detectors", () => {
  it("detects hardcoded secret values", () => {
    const code = `
      const apiKey = "sk_live_1234567890123456";
      const token = "ghp_abcdefghijklmnopqrstuvwxyz123456";
    `;
    const parsed = parseSource(code, "secret.ts");
    const findings = runPatternDetectors(parsed.ast, parsed.filePath);
    const ids = findings.map((f) => f.id);
    expect(ids).toContain("secret-stripe");
    expect(ids).toContain("secret-github");
  });

  it("detects high-entropy secrets", () => {
    const code = `
      const secret = "Xy1Q9zT8pLm2Nw5Vb7cR3dE6fGh4Jk0S";
    `;
    const parsed = parseSource(code, "entropy.ts");
    const findings = runPatternDetectors(parsed.ast, parsed.filePath);
    const titles = findings.map((f) => f.title);
    expect(titles).toContain("Hardcoded Secret");
  });

  it("detects weak crypto usage", () => {
    const code = `
      import crypto from "node:crypto";
      crypto.createHash("md5");
      crypto.createCipher("aes-256-ecb", "secret");
      crypto.createCipheriv("des-ede3", Buffer.alloc(8), Buffer.alloc(8));
      Math.random();
    `;
    const parsed = parseSource(code, "crypto.ts");
    const findings = runPatternDetectors(parsed.ast, parsed.filePath);
    const titles = findings.map((f) => f.title);
    expect(titles).toContain("Weak Hash Function");
    expect(titles).toContain("Insecure Cipher API");
    expect(titles).toContain("Weak Cipher Algorithm");
    expect(titles).toContain("Insecure Randomness");
  });

  it("detects unsafe deserialization", () => {
    const code = `
      import serialize from "node-serialize";
      serialize.unserialize(userInput);
      YAML.load(userInput);
    `;
    const parsed = parseSource(code, "deserialize.ts");
    const findings = runPatternDetectors(parsed.ast, parsed.filePath);
    const ids = findings.map((f) => f.id);
    expect(ids).toContain("unsafe-deserialization");
  });
});
