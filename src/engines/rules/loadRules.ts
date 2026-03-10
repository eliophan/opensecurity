import fs from "node:fs/promises";
import path from "node:path";
import type { OwaspRule } from "../analysis/rules.js";
import { DEFAULT_RULES } from "./defaultRules.js";

export async function loadRules(rulesPath: string | undefined, cwd: string): Promise<OwaspRule[]> {
  if (!rulesPath) return DEFAULT_RULES;
  const resolved = path.isAbsolute(rulesPath) ? rulesPath : path.join(cwd, rulesPath);
  const raw = await fs.readFile(resolved, "utf8");
  const parsed = JSON.parse(raw) as unknown;
  if (!Array.isArray(parsed)) {
    throw new Error("Rules file must be a JSON array");
  }
  return parsed as OwaspRule[];
}
