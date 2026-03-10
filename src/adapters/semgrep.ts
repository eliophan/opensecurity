import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Adapter } from "./types.js";
import type { Severity } from "../scan.js";
import { SEMGREP_EXTS, matchesExtension } from "./languages.js";
import { commandExists, extractJsonFromOutput, normalizePath, unique } from "./utils.js";

const execFileAsync = promisify(execFile);

function mapSeverity(level?: string): Severity {
  const norm = (level ?? "").toLowerCase();
  if (norm === "critical") return "critical";
  if (norm === "error" || norm === "high") return "high";
  if (norm === "warning" || norm === "medium") return "medium";
  return "low";
}

function uniqueDirs(relPaths: string[]): string[] {
  return unique(relPaths.map((relPath) => {
    const dir = relPath.includes("/") ? relPath.slice(0, relPath.lastIndexOf("/")) : ".";
    return dir === "" ? "." : dir;
  }));
}

export const semgrepAdapter: Adapter = {
  id: "semgrep",
  name: "Semgrep",
  languages: [
    "Java",
    "C#",
    "PHP",
    "Rust",
    "Kotlin",
    "Swift",
    "C/C++"
  ],
  matchFile: (filePath) => matchesExtension(filePath, SEMGREP_EXTS),
  isAvailable: () => commandExists("semgrep"),
  async run(context) {
    const { cwd, relPaths } = context;
    if (!relPaths.length) return [];
    const targets = relPaths.length > 200 ? uniqueDirs(relPaths) : unique(relPaths);
    const args = ["--config", "auto", "--json", "--quiet", ...targets];
    const { stdout, stderr } = await execFileAsync("semgrep", args, {
      cwd,
      maxBuffer: 20 * 1024 * 1024
    });
    const json = extractJsonFromOutput(stdout, stderr);
    const results = Array.isArray(json?.results) ? json.results : [];
    return results.map((item: any) => ({
      id: item.check_id ?? "semgrep",
      severity: mapSeverity(item.extra?.severity),
      title: item.extra?.message ?? item.check_id ?? "Semgrep issue",
      description: item.extra?.message ?? "Semgrep issue detected.",
      file: normalizePath(item.path ?? "", cwd),
      line: item.start?.line ? Number(item.start.line) : undefined,
      column: item.start?.col ? Number(item.start.col) : undefined,
      category: "code"
    }));
  }
};
