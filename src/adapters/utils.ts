import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export async function commandExists(command: string): Promise<boolean> {
  const isWin = process.platform === "win32";
  const lookup = isWin ? "where" : "which";
  try {
    await execFileAsync(lookup, [command]);
    return true;
  } catch {
    return false;
  }
}

export function normalizePath(filePath: string, cwd: string): string {
  const rel = path.isAbsolute(filePath) ? path.relative(cwd, filePath) : filePath;
  return rel.split(path.sep).join("/");
}

export function tryParseJson(raw: string): any | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    return null;
  }
}

export function extractJsonFromOutput(stdout: string, stderr: string): any | null {
  const parsed = tryParseJson(stdout);
  if (parsed) return parsed;
  const parsedErr = tryParseJson(stderr);
  if (parsedErr) return parsedErr;
  const combined = `${stdout}\n${stderr}`.trim();
  if (!combined) return null;
  const start = combined.search(/[\[{]/);
  if (start === -1) return null;
  const end = Math.max(combined.lastIndexOf("}"), combined.lastIndexOf("]"));
  if (end <= start) return null;
  const slice = combined.slice(start, end + 1);
  return tryParseJson(slice);
}

export function unique<T>(items: T[]): T[] {
  return Array.from(new Set(items));
}
