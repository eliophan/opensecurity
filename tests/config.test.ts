import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { getGlobalConfigPath, loadGlobalConfig, saveGlobalConfig, loadProjectConfig } from "../src/core/config.js";

async function createTempDir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "opensecurity-"));
}

describe("config", () => {
  it("loads and saves global config", async () => {
    const temp = await createTempDir();
    const env = { OPENSECURITY_CONFIG_HOME: temp } as NodeJS.ProcessEnv;

    await saveGlobalConfig({ apiKey: "test" }, env);
    const config = await loadGlobalConfig(env);

    expect(config.apiKey).toBe("test");
    expect(config.baseUrl).toBeDefined();
    expect(await fs.readFile(getGlobalConfigPath(env), "utf8")).toContain("test");
  });

  it("loads project config when present", async () => {
    const temp = await createTempDir();
    const projectPath = path.join(temp, ".opensecurity.json");
    await fs.writeFile(projectPath, JSON.stringify({ include: ["src/**"] }), "utf8");

    const config = await loadProjectConfig(temp);
    expect(config.include).toEqual(["src/**"]);
  });
});
