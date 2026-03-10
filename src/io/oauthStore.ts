import fs from "node:fs/promises";
import path from "node:path";
import { getConfigDir } from "../core/config.js";

export type OAuthProfile = {
  id: string;
  provider: "codex";
  accessToken: string;
  refreshToken?: string;
  tokenType?: string;
  scope?: string;
  expiresAt?: number;
  obtainedAt: number;
};

type OAuthStore = {
  profiles: OAuthProfile[];
};

const DEFAULT_PROFILE_ID = "codex";

export function getAuthProfilesPath(env = process.env): string {
  return path.join(getConfigDir(env), "auth-profiles.json");
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

export async function loadAuthStore(env = process.env): Promise<OAuthStore> {
  const filePath = getAuthProfilesPath(env);
  const existing = await readJsonFile<OAuthStore>(filePath);
  return existing ?? { profiles: [] };
}

export async function saveAuthStore(store: OAuthStore, env = process.env): Promise<void> {
  await writeJsonFile(getAuthProfilesPath(env), store);
}

export async function saveOAuthProfile(
  profile: Omit<OAuthProfile, "id"> & { id?: string },
  env = process.env
): Promise<OAuthProfile> {
  const store = await loadAuthStore(env);
  const id = profile.id ?? DEFAULT_PROFILE_ID;
  const normalized: OAuthProfile = { ...profile, id };
  const next = store.profiles.filter((p) => p.id !== id);
  next.push(normalized);
  await saveAuthStore({ profiles: next }, env);
  return normalized;
}

export async function getOAuthProfile(
  id: string,
  env = process.env
): Promise<OAuthProfile | null> {
  const store = await loadAuthStore(env);
  return store.profiles.find((p) => p.id === id) ?? null;
}

export function isTokenExpired(profile: OAuthProfile, skewMs = 60_000): boolean {
  if (!profile.expiresAt) return false;
  return Date.now() + skewMs >= profile.expiresAt;
}
