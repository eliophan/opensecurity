import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { listMatchedFiles, scan, chunkCodeByBoundary } from "../src/core/scan.js";
import { parseSource } from "../src/engines/analysis/ast.js";

async function createTempDir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "opensecurity-"));
}

describe("scan options", () => {
  it("dry-run does not require api key and returns empty findings", async () => {
    const root = await createTempDir();
    await fs.writeFile(path.join(root, "a.ts"), "console.log('ok')");

    const result = await scan({ cwd: root, dryRun: true });
    expect(result.findings).toEqual([]);
  });

  it("CLI include/exclude overrides project config", async () => {
    const root = await createTempDir();
    await fs.writeFile(path.join(root, "a.ts"), "console.log('ok')");
    await fs.writeFile(path.join(root, "README.md"), "readme");
    await fs.writeFile(
      path.join(root, ".opensecurity.json"),
      JSON.stringify({ include: ["**/*.ts"], exclude: ["**/*.md"] }),
      "utf8"
    );

    const files = await listMatchedFiles({
      cwd: root,
      include: ["**/*.md"],
      exclude: []
    });

    const rel = files.map((f) => path.relative(root, f)).sort();
    expect(rel).toEqual(["README.md"]);
  });

  it("runs rule-based scan without API key", async () => {
    const root = await createTempDir();
    const prevConfigHome = process.env.OPENSECURITY_CONFIG_HOME;
    process.env.OPENSECURITY_CONFIG_HOME = path.join(root, ".config");
    await fs.writeFile(
      path.join(root, "a.ts"),
      "const input = getUserInput();\\n eval(input);",
      "utf8"
    );

    const result = await scan({ cwd: root, include: ["**/*.ts"], exclude: [] });
    const hasEvalRule = result.findings.some((finding) => finding.id === "js-eval-injection");
    expect(hasEvalRule).toBe(true);

    if (prevConfigHome === undefined) {
      delete process.env.OPENSECURITY_CONFIG_HOME;
    } else {
      process.env.OPENSECURITY_CONFIG_HOME = prevConfigHome;
    }
  });

  it("detects path traversal via filesystem sinks", async () => {
    const root = await createTempDir();
    const prevConfigHome = process.env.OPENSECURITY_CONFIG_HOME;
    process.env.OPENSECURITY_CONFIG_HOME = path.join(root, ".config");
    await fs.writeFile(
      path.join(root, "a.ts"),
      "import fs from 'node:fs';\nconst input = getUserInput();\nfs.readFile(input, () => {});",
      "utf8"
    );

    const result = await scan({ cwd: root, include: ["**/*.ts"], exclude: [] });
    const hasRule = result.findings.some((finding) => finding.id === "js-path-traversal");
    expect(hasRule).toBe(true);

    if (prevConfigHome === undefined) {
      delete process.env.OPENSECURITY_CONFIG_HOME;
    } else {
      process.env.OPENSECURITY_CONFIG_HOME = prevConfigHome;
    }
  });

  it("chunks along function boundaries", async () => {
    const code = `
      const shared = "ok";
      function alpha() {
        const input = getUserInput();
        return input + shared;
      }
      function beta() {
        return shared;
      }
    `;
    const parsed = parseSource(code, "test.ts");
    const chunks = chunkCodeByBoundary(code, parsed.ast, 1000);

    expect(chunks.length).toBe(3);
    const alphaChunk = chunks.find((chunk) => chunk.includes("function alpha"));
    const betaChunk = chunks.find((chunk) => chunk.includes("function beta"));
    expect(alphaChunk).toContain("return input + shared;");
    expect(betaChunk).toContain("return shared;");
  });
});
