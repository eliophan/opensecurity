import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

async function createTempDir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "opensecurity-"));
}

async function runCli(args: string[]): Promise<{ stdout: string; stderr: string }> {
  const cliPath = path.resolve("src/cli.ts");
  const nodeArgs = ["--import", "tsx", cliPath, ...args];
  const { stdout, stderr } = await execFileAsync(process.execPath, nodeArgs, {
    cwd: process.cwd(),
    env: process.env
  });
  return { stdout: stdout.trim(), stderr: stderr.trim() };
}

describe("cli --dry-run", () => {
  it("prints matched files as relative paths", async () => {
    const root = await createTempDir();
    await fs.mkdir(path.join(root, "src"), { recursive: true });
    await fs.writeFile(path.join(root, "src", "index.ts"), "console.log('ok')");
    await fs.writeFile(path.join(root, "README.md"), "readme");

    const result = await runCli([
      "scan",
      "--dry-run",
      "--cwd",
      root,
      "--include",
      "**/*.ts"
    ]);

    // stderr may contain progress/info messages (not errors)
    expect(result.stderr).not.toContain("Error");
    expect(result.stdout.split(/\r?\n/).sort()).toEqual(["src/index.ts"]);
  });
});
