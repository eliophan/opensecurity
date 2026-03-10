import fs from "node:fs/promises";
import path from "node:path";
import semver from "semver";
import type { CveRecord, Dependency } from "./types.js";

export type CveLookup = {
  lookup(dependency: Dependency): Promise<CveRecord[]>;
};

export type CveLookupOptions = {
  cachePath?: string;
  apiUrl?: string;
};

export function createCveLookup(options: CveLookupOptions, cwd: string): CveLookup {
  if (options.cachePath) {
    return new LocalCveLookup(options.cachePath, cwd);
  }
  if (options.apiUrl) {
    return new ApiCveLookup(options.apiUrl);
  }
  return new EmptyCveLookup();
}

class EmptyCveLookup implements CveLookup {
  async lookup(): Promise<CveRecord[]> {
    return [];
  }
}

class LocalCveLookup implements CveLookup {
  private cache: CveRecord[] | null = null;
  private cachePath: string;

  constructor(cachePath: string, cwd: string) {
    this.cachePath = path.isAbsolute(cachePath) ? cachePath : path.join(cwd, cachePath);
  }

  async lookup(dependency: Dependency): Promise<CveRecord[]> {
    const cache = await this.load();
    return cache.filter((record) => matchesDependency(record, dependency));
  }

  private async load(): Promise<CveRecord[]> {
    if (this.cache) return this.cache;
    const raw = await fs.readFile(this.cachePath, "utf8");
    const parsed = JSON.parse(raw) as any;
    const list = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.vulnerabilities) ? parsed.vulnerabilities : [];
    this.cache = list as CveRecord[];
    return this.cache;
  }
}

class ApiCveLookup implements CveLookup {
  constructor(private apiUrl: string) {}

  async lookup(dependency: Dependency): Promise<CveRecord[]> {
    const body = {
      package: { name: dependency.name, ecosystem: dependency.ecosystem === "pypi" ? "PyPI" : "npm" },
      version: dependency.version ?? dependency.spec
    };
    const res = await fetch(this.apiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    if (!res.ok) return [];
    const data = await res.json();
    const vulns = Array.isArray(data?.vulns) ? data.vulns : [];
    return vulns.map((v: any) => normalizeOsvRecord(v));
  }
}

function normalizeOsvRecord(record: any): CveRecord {
  const severity = record?.severity?.[0]?.type === "CVSS_V3" ? mapCvss(record?.severity?.[0]?.score) : undefined;
  const cvssScore = record?.severity?.[0]?.score ? Number(record.severity[0].score) : undefined;
  return {
    id: record?.id ?? "UNKNOWN",
    package: record?.package?.name ?? "unknown",
    ecosystem: record?.package?.ecosystem === "PyPI" ? "pypi" : "npm",
    affectedRange: record?.affected?.[0]?.ranges?.[0]?.events
      ?.map((e: any) => (e.introduced ? `>=${e.introduced}` : e.fixed ? `<${e.fixed}` : ""))
      .join(" "),
    fixedVersion: record?.affected?.[0]?.ranges?.[0]?.events?.find((e: any) => e.fixed)?.fixed,
    severity,
    cvssScore,
    description: record?.summary ?? record?.details,
    references: record?.references?.map((r: any) => r.url).filter(Boolean)
  };
}

function mapCvss(score?: string): CveRecord["severity"] {
  const numeric = Number(score);
  if (Number.isNaN(numeric)) return undefined;
  if (numeric >= 9) return "critical";
  if (numeric >= 7) return "high";
  if (numeric >= 4) return "medium";
  return "low";
}

function matchesDependency(record: CveRecord, dep: Dependency): boolean {
  if (record.ecosystem && record.ecosystem !== dep.ecosystem) return false;
  if (record.package !== dep.name) return false;
  if (!record.affectedRange) return true;
  if (!dep.version) return true;
  if (dep.ecosystem === "npm" && semver.valid(dep.version)) {
    return semver.satisfies(dep.version, record.affectedRange, { includePrerelease: true });
  }
  return true;
}
