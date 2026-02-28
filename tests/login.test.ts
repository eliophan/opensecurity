import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { login } from "../src/login.js";
import { getGlobalConfigPath } from "../src/config.js";

async function createTempDir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "opensecurity-"));
}

describe("login", () => {
  it("stores api key from env", async () => {
    const temp = await createTempDir();
    const env = {
      OPENSECURITY_CONFIG_HOME: temp,
      CODEX_API_KEY: "env-key"
    } as NodeJS.ProcessEnv;

    const config = await login(env, async () => "");
    const saved = await fs.readFile(getGlobalConfigPath(env), "utf8");

    expect(config.apiKey).toBe("env-key");
    expect(saved).toContain("env-key");
  });
});
