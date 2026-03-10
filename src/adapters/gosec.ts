import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import type { Adapter } from "./types.js";
import type { Severity } from "../scan.js";
import { GO_EXTS, matchesExtension } from "./languages.js";
import { commandExists, extractJsonFromOutput, normalizePath, unique } from "./utils.js";

const execFileAsync = promisify(execFile);

function mapSeverity(level?: string): Severity {
  const norm = (level ?? "").toLowerCase();
  if (norm === "high") return "high";
  if (norm === "medium") return "medium";
  return "low";
}

function uniqueDirs(relPaths: string[]): string[] {
  return unique(relPaths.map((relPath) => {
    const dir = path.dirname(relPath);
    return dir === "." ? "." : dir;
  }));
}

export const gosecAdapter: Adapter = {
  id: "gosec",
  name: "gosec",
  languages: ["Go"],
  matchFile: (filePath) => matchesExtension(filePath, GO_EXTS),
  isAvailable: () => commandExists("gosec"),
  async run(context) {
    const { cwd, relPaths } = context;
    if (!relPaths.length) return [];
    const dirs = uniqueDirs(relPaths);
    const args = ["-fmt", "json", ...dirs];
    const { stdout, stderr } = await execFileAsync("gosec", args, {
      cwd,
      maxBuffer: 10 * 1024 * 1024
    });
    const json = extractJsonFromOutput(stdout, stderr);
    const issues = Array.isArray(json?.Issues) ? json.Issues : Array.isArray(json?.issues) ? json.issues : [];
    return issues.map((item: any) => ({
      id: item.rule_id ?? item.rule ?? "gosec",
      severity: mapSeverity(item.severity),
      title: item.details ?? item.what ?? "gosec issue",
      description: item.details ?? item.what ?? "gosec issue detected.",
      file: normalizePath(item.file ?? item.filename ?? "", cwd),
      line: item.line ? Number(item.line) : undefined,
      category: "code"
    }));
  }
};
