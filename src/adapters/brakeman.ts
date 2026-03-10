import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Adapter } from "./types.js";
import type { Severity } from "../scan.js";
import { RUBY_EXTS, matchesExtension } from "./languages.js";
import { commandExists, extractJsonFromOutput, normalizePath } from "./utils.js";

const execFileAsync = promisify(execFile);

function mapSeverity(confidence?: string): Severity {
  const norm = (confidence ?? "").toLowerCase();
  if (norm === "high") return "high";
  if (norm === "medium") return "medium";
  if (norm === "low") return "low";
  return "medium";
}

export const brakemanAdapter: Adapter = {
  id: "brakeman",
  name: "Brakeman",
  languages: ["Ruby"],
  matchFile: (filePath) => matchesExtension(filePath, RUBY_EXTS),
  isAvailable: () => commandExists("brakeman"),
  async run(context) {
    const { cwd } = context;
    const args = ["-f", "json", "-q"];
    const { stdout, stderr } = await execFileAsync("brakeman", args, {
      cwd,
      maxBuffer: 10 * 1024 * 1024
    });
    const json = extractJsonFromOutput(stdout, stderr);
    const warnings = Array.isArray(json?.warnings) ? json.warnings : [];
    return warnings.map((item: any) => ({
      id: item.warning_code ?? item.warning_type ?? "brakeman",
      severity: mapSeverity(item.confidence),
      title: item.warning_type ?? item.message ?? "Brakeman warning",
      description: item.message ?? "Brakeman warning detected.",
      file: normalizePath(item.file ?? "", cwd),
      line: item.line ? Number(item.line) : undefined,
      category: "code"
    }));
  }
};
