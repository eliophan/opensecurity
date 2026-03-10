import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Adapter } from "./types.js";
import type { Severity } from "../scan.js";
import { PYTHON_EXTS, matchesExtension } from "./languages.js";
import { commandExists, extractJsonFromOutput, normalizePath } from "./utils.js";

const execFileAsync = promisify(execFile);

function mapSeverity(level?: string): Severity {
  const norm = (level ?? "").toLowerCase();
  if (norm === "high") return "high";
  if (norm === "medium") return "medium";
  return "low";
}

export const banditAdapter: Adapter = {
  id: "bandit",
  name: "Bandit",
  languages: ["Python"],
  matchFile: (filePath) => matchesExtension(filePath, PYTHON_EXTS),
  isAvailable: () => commandExists("bandit"),
  async run(context) {
    const { cwd, relPaths } = context;
    if (!relPaths.length) return [];
    const args = ["-f", "json", ...relPaths];
    const { stdout, stderr } = await execFileAsync("bandit", args, {
      cwd,
      maxBuffer: 10 * 1024 * 1024
    });
    const json = extractJsonFromOutput(stdout, stderr);
    const results = Array.isArray(json?.results) ? json.results : [];
    return results.map((item: any) => ({
      id: item.test_id ?? "bandit",
      severity: mapSeverity(item.issue_severity),
      title: item.test_name ?? item.issue_text ?? "Bandit issue",
      description: item.issue_text ?? "Bandit issue detected.",
      file: normalizePath(item.filename ?? "", cwd),
      line: item.line_number ? Number(item.line_number) : undefined,
      category: "code"
    }));
  }
};
