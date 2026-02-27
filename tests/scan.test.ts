import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { listMatchedFiles, scan } from "../src/scan.js";

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
});
