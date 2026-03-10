import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

export type Provider = "openai" | "anthropic" | "google" | "mistral" | "xai" | "cohere";

export type GlobalConfig = {
  provider?: Provider;
  apiKey?: string;
  baseUrl?: string;
  model?: string;
  apiType?: "responses" | "chat";
  authMode?: "oauth" | "api_key";
  authProfileId?: string;
  oauthProvider?: "codex-cli" | "proxy";
  providerApiKey?: string;
  providerBaseUrl?: string;
};

export type ProjectConfig = {
  include?: string[];
  exclude?: string[];
  rulesPath?: string;
  cveCachePath?: string;
  cveApiUrl?: string;
  dataSensitivity?: "low" | "medium" | "high";
  maxChars?: number;
  concurrency?: number;
};

export const DEFAULT_INCLUDE = ["**/*"];
export const DEFAULT_EXCLUDE = [
  "**/.git/**",
  "**/node_modules/**",
  "**/dist/**",
  "**/build/**",
  "**/coverage/**",
  "**/.opensecurity.json"
];

const DEFAULT_GLOBALS: Required<Pick<GlobalConfig, "baseUrl" | "model" | "apiType" | "provider">> = {
  baseUrl: "https://api.openai.com/v1/responses",
  model: "gpt-4o-mini",
  apiType: "responses",
  provider: "openai"
};

export function getConfigDir(env = process.env): string {
  const override = env.OPENSECURITY_CONFIG_HOME;
  if (override && override.trim()) return override;
  return path.join(os.homedir(), ".config", "opensecurity");
}

export function getGlobalConfigPath(env = process.env): string {
  return path.join(getConfigDir(env), "config.json");
}

export function getProjectConfigPath(cwd = process.cwd()): string {
  return path.join(cwd, ".opensecurity.json");
}

async function readJsonFile<T>(filePath: string): Promise<T | null> {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    return JSON.parse(raw) as T;
  } catch (err: any) {
    if (err?.code === "ENOENT") return null;
    throw err;
  }
}

async function writeJsonFile(filePath: string, data: unknown): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(data, null, 2), "utf8");
}

export async function loadGlobalConfig(env = process.env): Promise<GlobalConfig> {
  const filePath = getGlobalConfigPath(env);
  const existing = await readJsonFile<GlobalConfig>(filePath);
  return {
    ...DEFAULT_GLOBALS,
    ...(existing ?? {})
  };
}

export async function saveGlobalConfig(config: GlobalConfig, env = process.env): Promise<void> {
  const current = await loadGlobalConfig(env);
  const merged = { ...current, ...config };
  await writeJsonFile(getGlobalConfigPath(env), merged);
}

export async function loadProjectConfig(cwd = process.cwd()): Promise<ProjectConfig> {
  const filePath = getProjectConfigPath(cwd);
  const existing = await readJsonFile<ProjectConfig>(filePath);
  return existing ?? {};
}

export function resolveProjectFilters(
  project: ProjectConfig
): Required<Pick<ProjectConfig, "include" | "exclude">> {
  return {
    include: project.include?.length ? project.include : [...DEFAULT_INCLUDE],
    exclude: project.exclude?.length ? project.exclude : [...DEFAULT_EXCLUDE]
  };
}
