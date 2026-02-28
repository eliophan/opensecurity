import fs from "node:fs/promises";
import path from "node:path";
import { loadGlobalConfig, loadProjectConfig, resolveProjectFilters } from "./config.js";
import { getOAuthProfile, isTokenExpired, saveOAuthProfile, type OAuthProfile } from "./oauthStore.js";
import { walkFiles } from "./fileWalker.js";
import { parseSource } from "./analysis/ast.js";
import { runRuleEngine } from "./analysis/rules.js";
import { loadRules } from "./rules/loadRules.js";
import { scanDependenciesWithCves } from "./deps/engine.js";

export type Severity = "low" | "medium" | "high" | "critical";

export type Finding = {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  file: string;
  line?: number;
  owasp?: string;
  category?: "code" | "dependency";
  packageName?: string;
  packageVersion?: string;
  cveId?: string;
  riskScore?: number;
  recommendation?: string;
  simulation?: { payload: string; impact: string };
};

export type ScanResult = {
  findings: Finding[];
};

export type ScanOptions = {
  cwd?: string;
  format?: "text" | "json";
  maxChars?: number;
  model?: string;
  authMode?: "oauth" | "api_key";
  include?: string[];
  exclude?: string[];
  rulesPath?: string;
  cveCachePath?: string;
  cveApiUrl?: string;
  simulate?: boolean;
  dataSensitivity?: "low" | "medium" | "high";
  dependencyOnly?: boolean;
  noAi?: boolean;
  dryRun?: boolean;
  concurrency?: number;
  maxRetries?: number;
  retryDelayMs?: number;
};

const DEFAULT_MAX_CHARS = 4000;
const DEFAULT_CONCURRENCY = 2;
const DEFAULT_MAX_RETRIES = 2;
const DEFAULT_RETRY_DELAY_MS = 500;
const MAX_ESTIMATED_TOKENS = 50000; // Guardrail: reject massive scans
const CHARS_PER_TOKEN = 4; // Simple heuristic for estimation

export async function scan(options: ScanOptions = {}): Promise<ScanResult> {
  const cwd = options.cwd ?? process.cwd();
  const { filters, globalConfig, projectConfig } = await resolveScanContext(options, cwd);
  const rules = await loadRules(options.rulesPath ?? projectConfig.rulesPath, cwd);

  const baseUrl = globalConfig.baseUrl ?? "https://api.openai.com/v1/responses";
  const authMode = globalConfig.authMode;
  const apiType = globalConfig.apiType ?? "responses";
  const model = options.model ?? globalConfig.model ?? "gpt-4o-mini";
  const maxChars = options.maxChars ?? DEFAULT_MAX_CHARS;
  const concurrency = Math.max(1, options.concurrency ?? DEFAULT_CONCURRENCY);
  const maxRetries = Math.max(0, options.maxRetries ?? DEFAULT_MAX_RETRIES);
  const retryDelayMs = Math.max(0, options.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS);

  const files = await walkFiles(cwd, filters);
  if (options.dryRun) {
    return { findings: [] };
  }
  const apiKey = await resolveAuthToken(globalConfig);
  const findings: Finding[] = [];

  if (authMode === "oauth" && baseUrl.includes("api.openai.com")) {
    throw new Error("OAuth mode requires a backend/proxy. Set OPENSECURITY_PROXY_URL or configure baseUrl to your backend.");
  }

  const tasks: Array<() => Promise<void>> = [];

  if (!options.dependencyOnly) {
    let totalEstimatedTokens = 0;
    for (const filePath of files) {
      if (isAnalyzableFile(filePath)) {
        const content = await fs.readFile(filePath, "utf8");
        totalEstimatedTokens += Math.ceil(content.length / CHARS_PER_TOKEN);
      }
    }

    if (apiKey && !options.noAi && totalEstimatedTokens > MAX_ESTIMATED_TOKENS) {
      throw new Error(`Scan size too large: Estimated ${totalEstimatedTokens} tokens exceeds guardrail limit of ${MAX_ESTIMATED_TOKENS}. Use --no-ai or narrow your scope.`);
    }

    for (const filePath of files) {
      const relPath = path.relative(cwd, filePath);
      const isCode = isAnalyzableFile(filePath);
      const content = await fs.readFile(filePath, "utf8");

      if (isCode) {
        // Static Rule Engine (Babel/AST)
        const parsed = parseSource(content, relPath);
        const ruleFindings = runRuleEngine(parsed.ast, relPath, rules);
        for (const finding of ruleFindings) {
          findings.push({
            id: finding.ruleId,
            severity: finding.severity,
            title: finding.ruleName,
            description: `${finding.message} [${finding.owasp}]`,
            file: finding.file,
            line: finding.line,
            owasp: finding.owasp,
            category: "code"
          });
        }
      }

      // AI Analysis
      if (apiKey && !options.noAi && isCode) {
        const chunks = chunkText(content, maxChars);
        for (let i = 0; i < chunks.length; i += 1) {
          const prompt = buildPrompt(relPath, chunks[i], i + 1, chunks.length);
          tasks.push(async () => {
            const responseText = await callModelWithRetry(
              {
                apiKey,
                baseUrl,
                apiType,
                model,
                prompt
              },
              maxRetries,
              retryDelayMs
            );

            const parsed = extractJson(responseText);
            if (!parsed?.findings) return;
            for (const finding of parsed.findings) {
              findings.push({
                ...finding,
                file: finding.file ?? relPath
              });
            }
          });
        }
      }
    }
  }

  const dependencyFindings = await scanDependenciesWithCves({
    cwd,
    cveLookup: {
      cachePath: options.cveCachePath ?? projectConfig.cveCachePath,
      apiUrl: options.cveApiUrl ?? projectConfig.cveApiUrl
    },
    simulate: options.simulate,
    dataSensitivity: options.dataSensitivity ?? projectConfig.dataSensitivity
  });

  for (const finding of dependencyFindings) {
    findings.push({
      id: finding.cve.id,
      severity: finding.risk.severity,
      title: `Dependency ${finding.dependency.name} vulnerable`,
      description: finding.cve.description ?? `Vulnerability in ${finding.dependency.name}`,
      file: path.relative(cwd, finding.dependency.source),
      category: "dependency",
      packageName: finding.dependency.name,
      packageVersion: finding.dependency.version ?? finding.dependency.spec,
      cveId: finding.cve.id,
      riskScore: finding.risk.score,
      recommendation: finding.recommendation,
      simulation: finding.simulation
    });
  }

  await runWithConcurrency(tasks, concurrency);

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
  const mergedGlobals = {
    ...globalConfig,
    authMode: options.authMode ?? globalConfig.authMode
  };
  return { globalConfig: mergedGlobals, projectConfig, filters };
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

async function resolveAuthToken(globalConfig: {
  apiKey?: string;
  authMode?: "oauth" | "api_key";
  authProfileId?: string;
}): Promise<string | undefined> {
  if (globalConfig.authMode !== "oauth") {
    return globalConfig.apiKey?.trim();
  }

  const profileId = globalConfig.authProfileId ?? "codex";
  const profile = await getOAuthProfile(profileId);
  if (!profile) {
    throw new Error("No OAuth profile found. Run login with --mode oauth.");
  }

  if (!isTokenExpired(profile)) {
    return profile.accessToken;
  }

  if (!profile.refreshToken) {
    throw new Error("OAuth token expired and no refresh token is available. Run login again.");
  }

  const refreshed = await refreshAccessToken(profile);
  await saveOAuthProfile(refreshed);
  return refreshed.accessToken;
}

async function refreshAccessToken(profile: OAuthProfile): Promise<OAuthProfile> {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: "app_EMoamEEZ73f0CkXaXp7hrann",
    refresh_token: profile.refreshToken ?? ""
  });

  const res = await fetch("https://auth.openai.com/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`OAuth refresh failed: ${res.status} ${text}`);
  }

  const data = (await res.json()) as {
    access_token?: string;
    refresh_token?: string;
    token_type?: string;
    expires_in?: number;
    scope?: string;
  };

  if (!data.access_token) {
    throw new Error("OAuth refresh did not return an access_token.");
  }

  const expiresAt = data.expires_in ? Date.now() + data.expires_in * 1000 : undefined;
  return {
    ...profile,
    accessToken: data.access_token,
    refreshToken: data.refresh_token ?? profile.refreshToken,
    tokenType: data.token_type ?? profile.tokenType,
    scope: data.scope ?? profile.scope,
    expiresAt,
    obtainedAt: Date.now()
  };
}

async function callModel(params: CallModelParams): Promise<string> {
  const { apiKey, baseUrl, apiType, model, prompt } = params;
  const headers = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${apiKey}`
  };

  const scrub = (msg: string) => msg.replace(apiKey, "sk-***" + apiKey.slice(-4));

  if (apiType === "chat" || baseUrl.includes("/chat/completions")) {
    const body = JSON.stringify({
      model,
      messages: [{ role: "user", content: prompt }],
      temperature: 0
    });
    const res = await fetch(baseUrl, { method: "POST", headers, body });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(scrub(`Model request failed: ${res.status} ${text}`));
    }
    const data = await res.json();
    return data?.choices?.[0]?.message?.content ?? "";
  }

  const body = JSON.stringify({
    model,
    input: prompt,
    temperature: 0
  });
  const res = await fetch(baseUrl, { method: "POST", headers, body });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(scrub(`Model request failed: ${res.status} ${text}`));
  }
  const data = await res.json();
  return data?.output_text ?? extractResponsesText(data);
}

async function callModelWithRetry(
  params: CallModelParams,
  maxRetries: number,
  retryDelayMs: number
): Promise<string> {
  let attempt = 0;
  let delay = retryDelayMs;
  // Simple exponential backoff with jitter
  while (true) {
    try {
      return await callModel(params);
    } catch (err) {
      if (attempt >= maxRetries) throw err;
      await sleep(delay + Math.floor(Math.random() * 100));
      delay = delay * 2;
      attempt += 1;
    }
  }
}

async function runWithConcurrency(tasks: Array<() => Promise<void>>, limit: number): Promise<void> {
  const queue = tasks.slice();
  const workers: Promise<void>[] = [];

  const worker = async () => {
    while (queue.length) {
      const task = queue.shift();
      if (!task) return;
      await task();
    }
  };

  for (let i = 0; i < limit; i += 1) {
    workers.push(worker());
  }

  await Promise.all(workers);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
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
      const owasp = item.owasp ? ` ${item.owasp}` : "";
      lines.push(`- [${item.id}] ${item.title}${owasp} (${location})`);
      lines.push(`  ${item.description}`);
      if (item.category === "dependency") {
        const pkg = item.packageVersion
          ? `${item.packageName}@${item.packageVersion}`
          : item.packageName ?? "unknown";
        const score = item.riskScore !== undefined ? ` score=${item.riskScore}` : "";
        const cve = item.cveId ? ` ${item.cveId}` : "";
        lines.push(`  package: ${pkg}${cve}${score}`);
      }
      if (item.recommendation) {
        lines.push(`  recommendation: ${item.recommendation}`);
      }
      if (item.simulation) {
        lines.push(`  simulate: ${item.simulation.payload}`);
      }
    }
    lines.push("");
  }

  return lines.join("\n").trim();
}

export function renderJsonReport(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

function isAnalyzableFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  // Only send text-based source files to the AI to prevent binary leakage or wasted tokens
  const supported = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".go", ".rs", ".java", ".c", ".cpp"];
  return supported.includes(ext);
}
