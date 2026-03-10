import fs from "node:fs/promises";
import path from "node:path";
import type { RuleSeverity, OwaspCategory } from "../analysis/rules.js";
import type { CallMatcher } from "../analysis/taint.js";
import type { NativeLanguageId } from "./languages.js";

export type NativeRuleKind = "taint" | "direct" | "secret";

export type NativeRule = {
  id: string;
  title: string;
  severity: RuleSeverity;
  owasp: OwaspCategory;
  kind: NativeRuleKind;
  sources?: Array<{ id: string; name: string; matcher: CallMatcher }>;
  sinks?: Array<{ id: string; name: string; matcher: CallMatcher }>;
  sanitizers?: Array<{ id: string; name: string; matcher: CallMatcher }>;
  callee?: string[] | string;
  calleePrefix?: string[] | string;
  calleePattern?: string[] | string;
  literalPattern?: string;
};

export type NativeRuleSet = {
  language: NativeLanguageId;
  rules: NativeRule[];
};

export async function loadNativeRules(baseDir: string, lang: NativeLanguageId): Promise<NativeRuleSet | null> {
  const rulePath = path.join(baseDir, "rules", "taint", `${lang}.json`);
  try {
    const raw = await fs.readFile(rulePath, "utf8");
    return JSON.parse(raw) as NativeRuleSet;
  } catch (err: any) {
    if (err?.code === "ENOENT") return null;
    throw err;
  }
}
