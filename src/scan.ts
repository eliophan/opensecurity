import fs from "node:fs/promises";
import path from "node:path";
import { loadGlobalConfig, loadProjectConfig, resolveProjectFilters } from "./config.js";
import { walkFiles } from "./fileWalker.js";

export type Severity = "low" | "medium" | "high" | "critical";

export type Finding = {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  file: string;
  line?: number;
};

export type ScanResult = {
  findings: Finding[];
};

export type ScanOptions = {
  cwd?: string;
  format?: "text" | "json";
  maxChars?: number;
  model?: string;
  include?: string[];
  exclude?: string[];
  dryRun?: boolean;
};

const DEFAULT_MAX_CHARS = 4000;

export async function scan(options: ScanOptions = {}): Promise<ScanResult> {
  const cwd = options.cwd ?? process.cwd();
  const { filters, globalConfig } = await resolveScanContext(options, cwd);

  const baseUrl = globalConfig.baseUrl ?? "https://api.openai.com/v1/responses";
  const apiType = globalConfig.apiType ?? "responses";
  const model = options.model ?? globalConfig.model ?? "gpt-4o-mini";
  const maxChars = options.maxChars ?? DEFAULT_MAX_CHARS;

  const files = await walkFiles(cwd, filters);
  if (options.dryRun) {
    return { findings: [] };
  }
  const apiKey = globalConfig.apiKey?.trim();
  if (!apiKey) throw new Error("Missing API key. Run `opensecurity login` first.");
  const findings: Finding[] = [];

  for (const filePath of files) {
    const relPath = path.relative(cwd, filePath);
    const content = await fs.readFile(filePath, "utf8");
    const chunks = chunkText(content, maxChars);

    for (let i = 0; i < chunks.length; i += 1) {
      const prompt = buildPrompt(relPath, chunks[i], i + 1, chunks.length);
      const responseText = await callModel({
        apiKey,
        baseUrl,
        apiType,
        model,
        prompt
      });

      const parsed = extractJson(responseText);
      if (!parsed?.findings) continue;
      for (const finding of parsed.findings) {
        findings.push({
          ...finding,
          file: finding.file ?? relPath
        });
      }
    }
  }

  return { findings };
}

export async function listMatchedFiles(options: ScanOptions = {}): Promise<string[]> {
  const cwd = options.cwd ?? process.cwd();
  const { filters } = await resolveScanContext(options, cwd);
  return walkFiles(cwd, filters);
}

async function resolveScanContext(options: ScanOptions, cwd: string) {
  const globalConfig = await loadGlobalConfig();
  const projectConfig = await loadProjectConfig(cwd);
  const filters = resolveProjectFilters({
    include: options.include ?? projectConfig.include,
    exclude: options.exclude ?? projectConfig.exclude
  });
  return { globalConfig, projectConfig, filters };
}

export function chunkText(text: string, maxChars: number): string[] {
  if (text.length <= maxChars) return [text];
  const chunks: string[] = [];
  let offset = 0;
  while (offset < text.length) {
    chunks.push(text.slice(offset, offset + maxChars));
    offset += maxChars;
  }
  return chunks;
}

function buildPrompt(filePath: string, chunk: string, index: number, total: number): string {
  return [
    "You are a security reviewer. Analyze the following code chunk and return JSON only.",
    "Schema:",
    "{\"findings\":[{\"id\":string,\"severity\":\"low|medium|high|critical\",\"title\":string,\"description\":string,\"file\":string,\"line\":number}]}",
    `File: ${filePath} (chunk ${index}/${total})`,
    "Code:",
    chunk
  ].join("\n");
}

type CallModelParams = {
  apiKey: string;
  baseUrl: string;
  apiType: "responses" | "chat";
  model: string;
  prompt: string;
};

async function callModel(params: CallModelParams): Promise<string> {
  const { apiKey, baseUrl, apiType, model, prompt } = params;
  const headers = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${apiKey}`
  };

  if (apiType === "chat" || baseUrl.includes("/chat/completions")) {
    const body = JSON.stringify({
      model,
      messages: [{ role: "user", content: prompt }],
      temperature: 0
    });
    const res = await fetch(baseUrl, { method: "POST", headers, body });
    if (!res.ok) throw new Error(`Model request failed: ${res.status} ${await res.text()}`);
    const data = await res.json();
    return data?.choices?.[0]?.message?.content ?? "";
  }

  const body = JSON.stringify({
    model,
    input: prompt,
    temperature: 0
  });
  const res = await fetch(baseUrl, { method: "POST", headers, body });
  if (!res.ok) throw new Error(`Model request failed: ${res.status} ${await res.text()}`);
  const data = await res.json();
  return data?.output_text ?? extractResponsesText(data);
}

function extractResponsesText(data: any): string {
  if (!data?.output?.length) return "";
  const chunks: string[] = [];
  for (const item of data.output) {
    if (!item?.content?.length) continue;
    for (const content of item.content) {
      if (content?.type === "output_text" && content?.text) chunks.push(content.text);
    }
  }
  return chunks.join("\n");
}

function extractJson(text: string): ScanResult | null {
  if (!text) return null;
  const firstBrace = text.indexOf("{");
  const lastBrace = text.lastIndexOf("}");
  if (firstBrace === -1 || lastBrace === -1 || lastBrace <= firstBrace) return null;
  const candidate = text.slice(firstBrace, lastBrace + 1);
  try {
    return JSON.parse(candidate) as ScanResult;
  } catch {
    return null;
  }
}

export function renderTextReport(result: ScanResult): string {
  const grouped: Record<Severity, Finding[]> = {
    critical: [],
    high: [],
    medium: [],
    low: []
  };

  for (const finding of result.findings) {
    grouped[finding.severity]?.push(finding);
  }

  const lines: string[] = [];
  const order: Severity[] = ["critical", "high", "medium", "low"];
  for (const severity of order) {
    const items = grouped[severity];
    if (!items.length) continue;
    lines.push(`${severity.toUpperCase()} (${items.length})`);
    for (const item of items) {
      const location = item.line ? `${item.file}:${item.line}` : item.file;
      lines.push(`- [${item.id}] ${item.title} (${location})`);
      lines.push(`  ${item.description}`);
    }
    lines.push("");
  }

  return lines.join("\n").trim();
}

export function renderJsonReport(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}
