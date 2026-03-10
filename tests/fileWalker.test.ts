import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { walkFiles } from "../src/io/fileWalker.js";

async function createTempDir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "opensecurity-"));
}

describe("walkFiles", () => {
  it("respects include/exclude patterns", async () => {
    const root = await createTempDir();
    await fs.mkdir(path.join(root, "src"), { recursive: true });
    await fs.mkdir(path.join(root, "node_modules", "lib"), { recursive: true });
    await fs.writeFile(path.join(root, "src", "index.ts"), "console.log('ok')");
    await fs.writeFile(path.join(root, "README.md"), "readme");
    await fs.writeFile(path.join(root, "node_modules", "lib", "skip.js"), "skip");

    const files = await walkFiles(root, {
      include: ["**/*.ts"],
      exclude: ["**/node_modules/**"]
    });

    const rel = files.map((f) => path.relative(root, f).split(path.sep).join("/")).sort();
    expect(rel).toEqual(["src/index.ts"]);
  });
});
