import fs from "node:fs/promises";
import path from "node:path";
import type { Dependency } from "./types.js";

export async function scanDependencies(root: string): Promise<Dependency[]> {
  const deps: Dependency[] = [];
  const pkgJsonPath = path.join(root, "package.json");
  const pkgLockPath = path.join(root, "package-lock.json");
  const requirementsPath = path.join(root, "requirements.txt");

  const [pkgJson, pkgLock, requirements] = await Promise.all([
    readJsonFile<Record<string, any>>(pkgJsonPath),
    readJsonFile<Record<string, any>>(pkgLockPath),
    readTextFile(requirementsPath)
  ]);

  const resolvedVersions = pkgLock ? parsePackageLock(pkgLock) : new Map<string, string>();

  if (pkgJson) {
    const depsFromPkg = parsePackageJson(pkgJson, pkgJsonPath);
    for (const dep of depsFromPkg) {
      const resolved = resolvedVersions.get(dep.name);
      deps.push({ ...dep, version: dep.version ?? resolved });
    }
  }

  if (requirements) {
    deps.push(...parseRequirements(requirements, requirementsPath));
  }

  return deps;
}

function parsePackageJson(data: Record<string, any>, source: string): Dependency[] {
  const deps: Dependency[] = [];
  const addDeps = (record: Record<string, string> | undefined, scope: Dependency["scope"]) => {
    if (!record) return;
    for (const [name, spec] of Object.entries(record)) {
      deps.push({
        name,
        spec,
        version: undefined,
        ecosystem: "npm",
        scope,
        source
      });
    }
  };

  addDeps(data.dependencies, "prod");
  addDeps(data.devDependencies, "dev");
  return deps;
}

function parsePackageLock(data: Record<string, any>): Map<string, string> {
  const versions = new Map<string, string>();

  if (data.packages && typeof data.packages === "object") {
    for (const [pkgPath, info] of Object.entries<any>(data.packages)) {
      if (!info || typeof info !== "object") continue;
      if (!info.name || !info.version) continue;
      versions.set(info.name, info.version);
      if (pkgPath === "" && info.dependencies) {
        for (const [name, version] of Object.entries<string>(info.dependencies)) {
          versions.set(name, version);
        }
      }
    }
  }

  if (data.dependencies && typeof data.dependencies === "object") {
    for (const [name, info] of Object.entries<any>(data.dependencies)) {
      if (info?.version) {
        versions.set(name, info.version);
      }
    }
  }

  return versions;
}

function parseRequirements(text: string, source: string): Dependency[] {
  const deps: Dependency[] = [];
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const [namePart, versionPart] = trimmed.split(/==|>=|<=|~=|!=|>/).map((s) => s.trim());
    if (!namePart) continue;
    const versionMatch = trimmed.match(/(==|>=|<=|~=|!=|>)(.+)$/);
    const spec = versionMatch ? `${versionMatch[1]}${versionMatch[2].trim()}` : undefined;
    deps.push({
      name: namePart,
      spec,
      version: versionPart && versionMatch?.[1] === "==" ? versionPart : undefined,
      ecosystem: "pypi",
      scope: "prod",
      source
    });
  }
  return deps;
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

async function readTextFile(filePath: string): Promise<string | null> {
  try {
    return await fs.readFile(filePath, "utf8");
  } catch (err: any) {
    if (err?.code === "ENOENT") return null;
    throw err;
  }
}
