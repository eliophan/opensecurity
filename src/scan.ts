import fs from "node:fs/promises";
import path from "node:path";
import traverseImport from "@babel/traverse";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import crypto from "node:crypto";
import { loadGlobalConfig, loadProjectConfig, resolveProjectFilters, type Provider } from "./config.js";
import { getOAuthProfile, isTokenExpired, saveOAuthProfile, type OAuthProfile } from "./oauthStore.js";
import { walkFiles } from "./fileWalker.js";
import { parseSource } from "./analysis/ast.js";
import { runRuleEngine } from "./analysis/rules.js";
import { runPatternDetectors } from "./analysis/patterns.js";
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
  column?: number;
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

export const SCHEMA_VERSION = "1.0.0";

export type ScanOptions = {
  cwd?: string;
  targetPath?: string;
  format?: "text" | "json";
  maxChars?: number;
  model?: string;
  authMode?: "oauth" | "api_key";
  provider?: Provider;
  liveOutput?: boolean;
  onProgress?: (info: {
    file: string;
    fileIndex: number;
    totalFiles: number;
    chunkIndex: number;
    totalChunks: number;
  }) => void;
  onOutputChunk?: (chunk: string) => void;
  include?: string[];
  exclude?: string[];
  rulesPath?: string;
  cveCachePath?: string;
  cveApiUrl?: string;
  simulate?: boolean;
  dataSensitivity?: "low" | "medium" | "high";
  dependencyOnly?: boolean;
  noAi?: boolean;
  aiAllText?: boolean;
  aiMultiAgent?: boolean;
  aiBatchSize?: number;
  aiBatchDepth?: number;
  aiCache?: boolean;
  aiCachePath?: string;
  diffOnly?: boolean;
  diffBase?: string;
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
  const resolvedRoot = options.targetPath
    ? path.resolve(options.cwd ?? process.cwd(), options.targetPath)
    : (options.cwd ?? process.cwd());
  const rootStats = await safeStat(resolvedRoot);
  const cwd = rootStats?.isDirectory() ? resolvedRoot : path.dirname(resolvedRoot);
  const targetFile = rootStats?.isFile() ? resolvedRoot : undefined;

  const { filters, globalConfig, projectConfig } = await resolveScanContext(options, cwd, targetFile);
  const rules = await loadRules(options.rulesPath ?? projectConfig.rulesPath, cwd);

  const provider = options.provider ?? globalConfig.provider ?? "openai";
  const baseUrl = globalConfig.baseUrl ?? "https://api.openai.com/v1/responses";
  const authMode = globalConfig.authMode;
  const oauthProvider = globalConfig.oauthProvider ?? "proxy";
  const apiType = globalConfig.apiType ?? "responses";
  const model = options.model ?? globalConfig.model ?? "gpt-4o-mini";
  const maxChars = options.maxChars ?? projectConfig.maxChars ?? DEFAULT_MAX_CHARS;
  const concurrency = Math.max(1, options.concurrency ?? projectConfig.concurrency ?? DEFAULT_CONCURRENCY);
  const maxRetries = Math.max(0, options.maxRetries ?? DEFAULT_MAX_RETRIES);
  const retryDelayMs = Math.max(0, options.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS);

  let files = await walkFiles(cwd, filters);
  if (options.diffOnly) {
    const changed = await getChangedFiles(cwd, options.diffBase ?? "HEAD");
    const changedSet = new Set(changed.map((p) => path.resolve(cwd, p)));
    files = files.filter((filePath) => changedSet.has(path.resolve(filePath)));
  }
  if (options.dryRun) {
    return { findings: [] };
  }
  const useCodexCli = provider === "openai" && authMode === "oauth" && oauthProvider === "codex-cli";
  const apiKey = useCodexCli ? undefined : await resolveProviderAuthToken(globalConfig, provider);
  const findings: Finding[] = [];

  if (!apiKey && !useCodexCli && provider !== "openai" && !options.noAi) {
    const envKey = getProviderEnvKey(provider);
    throw new Error(
      `Missing API key for ${provider}. Set ${envKey} or run login with --provider ${provider} to continue.`
    );
  }

  if (provider !== "openai" && authMode === "oauth") {
    throw new Error("OAuth mode is only supported for OpenAI. Use api_key for other providers.");
  }

  if (provider === "openai" && authMode === "oauth" && oauthProvider !== "codex-cli" && baseUrl.includes("api.openai.com")) {
    throw new Error("OAuth mode requires a backend/proxy. Set OPENSECURITY_PROXY_URL or configure baseUrl to your backend.");
  }

  const tasks: Array<() => Promise<void>> = [];
  const cacheEnabled = options.aiCache ?? projectConfig.aiCache ?? true;
  const cachePath = resolveCachePath(cwd, options.aiCachePath ?? projectConfig.aiCachePath);
  const aiCache = cacheEnabled ? await loadAiCache(cachePath) : { entries: new Map<string, CachedAiEntry>() };
  const aiFindingsByFile = new Map<string, Finding[]>();

  if (!options.dependencyOnly) {
    const totalCodeFiles = files.filter((filePath) => isAnalyzableFile(filePath)).length;
    let codeFileIndex = 0;
    let totalEstimatedTokens = 0;

    const aiEligibleFiles = (options.aiAllText ?? true)
      ? files.filter((filePath) => isLikelyTextFile(filePath))
      : files.filter((filePath) => isAnalyzableFile(filePath));

    const codeFiles: Array<{
      absPath: string;
      relPath: string;
      content: string;
      parsed: ReturnType<typeof parseSource>;
    }> = [];

    for (const filePath of aiEligibleFiles) {
      if (!isAnalyzableFile(filePath)) continue;
      const content = await fs.readFile(filePath, "utf8");
      totalEstimatedTokens += Math.ceil(content.length / CHARS_PER_TOKEN);
      const relPath = path.relative(cwd, filePath);
      const parsed = parseSource(content, relPath);
      codeFiles.push({ absPath: filePath, relPath, content, parsed });
    }

    if (options.aiAllText ?? true) {
      for (const filePath of aiEligibleFiles) {
        if (isAnalyzableFile(filePath)) continue;
        const content = await fs.readFile(filePath, "utf8");
        totalEstimatedTokens += Math.ceil(content.length / CHARS_PER_TOKEN);
      }
    }

    if (apiKey && !options.noAi && totalEstimatedTokens > MAX_ESTIMATED_TOKENS) {
      throw new Error(`Scan size too large: Estimated ${totalEstimatedTokens} tokens exceeds guardrail limit of ${MAX_ESTIMATED_TOKENS}. Use --no-ai or narrow your scope.`);
    }

    const codeByPath = new Map<string, { relPath: string; content: string; parsed: ReturnType<typeof parseSource> }>();
    for (const file of codeFiles) {
      codeByPath.set(file.absPath, { relPath: file.relPath, content: file.content, parsed: file.parsed });
    }

    for (const file of codeFiles) {
      codeFileIndex += 1;
      // Static Rule Engine (Babel/AST)
      const ruleFindings = runRuleEngine(file.parsed.ast, file.relPath, rules);
      for (const finding of ruleFindings) {
        findings.push({
          id: finding.ruleId,
          severity: finding.severity,
          title: finding.ruleName,
          description: `${finding.message} [${finding.owasp}]`,
          file: finding.file,
          line: finding.line,
          column: finding.column,
          owasp: finding.owasp,
          category: "code"
        });
      }

      const patternFindings = runPatternDetectors(file.parsed.ast, file.relPath);
      for (const finding of patternFindings) {
        findings.push({
          id: finding.id,
          severity: finding.severity,
          title: finding.title,
          description: `${finding.description} [${finding.owasp}]`,
          file: finding.file,
          line: finding.line,
          column: finding.column,
          owasp: finding.owasp,
          category: "code"
        });
      }

    }

    if ((apiKey || useCodexCli) && !options.noAi) {
      if (options.aiMultiAgent) {
        const batchSize = Math.max(1, options.aiBatchSize ?? 25);
        const batchDepth = Math.max(1, options.aiBatchDepth ?? 2);
        const leaderContext = await buildLeaderContext(cwd);
        const relPaths = aiEligibleFiles.map((filePath) => path.relative(cwd, filePath));
        const grouped = groupFilesByModule(relPaths, batchDepth);
        const batches = createBatches(grouped, batchSize);
        let fileCounter = 0;

        for (const batch of batches) {
          tasks.push(async () => {
            for (const relPath of batch.files) {
              fileCounter += 1;
              const absPath = path.resolve(cwd, relPath);
              const cached = codeByPath.get(absPath);
              const content = cached?.content ?? await fs.readFile(absPath, "utf8");
              const cacheKey = cacheEnabled ? computeCacheKey(provider, model, content) : undefined;
              if (cacheKey) {
                const cachedEntry = aiCache.entries.get(relPath);
                if (cachedEntry && cachedEntry.hash === cacheKey) {
                  const cachedFindings = cachedEntry.findings.map((f) => ({ ...f }));
                  for (const finding of cachedFindings) {
                    findings.push(finding);
                  }
                  aiFindingsByFile.set(relPath, cachedFindings);
                  continue;
                }
              }
              const chunks = cached?.parsed
                ? chunkCodeByBoundary(content, cached.parsed.ast, maxChars)
                : chunkText(content, maxChars);

              for (let i = 0; i < chunks.length; i += 1) {
                const prompt = buildPromptWithContext(relPath, chunks[i], i + 1, chunks.length, leaderContext);
                if (options.onProgress) {
                  options.onProgress({
                    file: relPath,
                    fileIndex: fileCounter,
                    totalFiles: relPaths.length,
                    chunkIndex: i + 1,
                    totalChunks: chunks.length
                  });
                }
                const parsed = useCodexCli
                  ? await callCodexCliWithRetry(
                      prompt,
                      maxRetries,
                      retryDelayMs,
                      options.liveOutput ? options.onOutputChunk : undefined
                    )
                  : await (async () => {
                      const responseText = await callModelWithRetry(
                        {
                          provider,
                          apiKey: apiKey!,
                          baseUrl: provider === "openai" ? baseUrl : globalConfig.providerBaseUrl,
                          apiType,
                          model,
                          prompt
                        },
                        maxRetries,
                        retryDelayMs
                      );
                      return extractJson(responseText);
                    })();

                if (!parsed?.findings) continue;
                const bucket = aiFindingsByFile.get(relPath) ?? [];
                for (const finding of parsed.findings) {
                  const normalized = { ...finding, file: finding.file ?? relPath } as Finding;
                  findings.push(normalized);
                  bucket.push(normalized);
                }
                aiFindingsByFile.set(relPath, bucket);
              }
            }
          });
        }
      } else {
        for (const file of codeFiles) {
          const chunks = chunkCodeByBoundary(file.content, file.parsed.ast, maxChars);
          for (let i = 0; i < chunks.length; i += 1) {
            const prompt = buildPrompt(file.relPath, chunks[i], i + 1, chunks.length);
            const fileIndex = codeFileIndex;
            const chunkIndex = i + 1;
            const totalChunks = chunks.length;
            tasks.push(async () => {
              const cacheKey = cacheEnabled ? computeCacheKey(provider, model, file.content) : undefined;
              if (cacheKey) {
                const cachedEntry = aiCache.entries.get(file.relPath);
                if (cachedEntry && cachedEntry.hash === cacheKey) {
                  const cachedFindings = cachedEntry.findings.map((f) => ({ ...f }));
                  for (const finding of cachedFindings) {
                    findings.push(finding);
                  }
                  aiFindingsByFile.set(file.relPath, cachedFindings);
                  return;
                }
              }
              if (options.onProgress) {
                options.onProgress({
                  file: file.relPath,
                  fileIndex,
                  totalFiles: totalCodeFiles,
                  chunkIndex,
                  totalChunks
                });
              }
              const parsed = useCodexCli
                ? await callCodexCliWithRetry(
                    prompt,
                    maxRetries,
                    retryDelayMs,
                    options.liveOutput ? options.onOutputChunk : undefined
                  )
                : await (async () => {
                    const responseText = await callModelWithRetry(
                      {
                        provider,
                        apiKey: apiKey!,
                        baseUrl: provider === "openai" ? baseUrl : globalConfig.providerBaseUrl,
                        apiType,
                        model,
                        prompt
                      },
                      maxRetries,
                      retryDelayMs
                    );
                    return extractJson(responseText);
                  })();

              if (!parsed?.findings) return;
              const bucket = aiFindingsByFile.get(file.relPath) ?? [];
              for (const finding of parsed.findings) {
                const normalized = { ...finding, file: finding.file ?? file.relPath } as Finding;
                findings.push(normalized);
                bucket.push(normalized);
              }
              aiFindingsByFile.set(file.relPath, bucket);
            });
          }
        }

        if (options.aiAllText ?? true) {
          const nonJsFiles = aiEligibleFiles.filter((filePath) => !isAnalyzableFile(filePath));
          for (const filePath of nonJsFiles) {
            const relPath = path.relative(cwd, filePath);
            const content = await fs.readFile(filePath, "utf8");
            const chunks = chunkText(content, maxChars);
            for (let i = 0; i < chunks.length; i += 1) {
              const prompt = buildPrompt(relPath, chunks[i], i + 1, chunks.length);
              const fileIndex = totalCodeFiles + 1;
              const chunkIndex = i + 1;
              const totalChunks = chunks.length;
              tasks.push(async () => {
                const cacheKey = cacheEnabled ? computeCacheKey(provider, model, content) : undefined;
                if (cacheKey) {
                  const cachedEntry = aiCache.entries.get(relPath);
                  if (cachedEntry && cachedEntry.hash === cacheKey) {
                    const cachedFindings = cachedEntry.findings.map((f) => ({ ...f }));
                    for (const finding of cachedFindings) {
                      findings.push(finding);
                    }
                    aiFindingsByFile.set(relPath, cachedFindings);
                    return;
                  }
                }
                if (options.onProgress) {
                  options.onProgress({
                    file: relPath,
                    fileIndex,
                    totalFiles: totalCodeFiles,
                    chunkIndex,
                    totalChunks
                  });
                }
                const parsed = useCodexCli
                  ? await callCodexCliWithRetry(
                      prompt,
                      maxRetries,
                      retryDelayMs,
                      options.liveOutput ? options.onOutputChunk : undefined
                    )
                  : await (async () => {
                      const responseText = await callModelWithRetry(
                        {
                          provider,
                          apiKey: apiKey!,
                          baseUrl: provider === "openai" ? baseUrl : globalConfig.providerBaseUrl,
                          apiType,
                          model,
                          prompt
                        },
                        maxRetries,
                        retryDelayMs
                      );
                      return extractJson(responseText);
                    })();

                if (!parsed?.findings) return;
                const bucket = aiFindingsByFile.get(relPath) ?? [];
                for (const finding of parsed.findings) {
                  const normalized = { ...finding, file: finding.file ?? relPath } as Finding;
                  findings.push(normalized);
                  bucket.push(normalized);
                }
                aiFindingsByFile.set(relPath, bucket);
              });
            }
          }
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

  if (cacheEnabled) {
    for (const [relPath, fileFindings] of aiFindingsByFile.entries()) {
      const absPath = path.resolve(cwd, relPath);
      try {
        const content = await fs.readFile(absPath, "utf8");
        const hash = computeCacheKey(provider, model, content);
        aiCache.entries.set(relPath, { hash, findings: fileFindings });
      } catch {
        // ignore missing files
      }
    }
    await saveAiCache(cachePath, aiCache);
  }

  return { findings: dedupeFindings(findings) };
}

export async function listMatchedFiles(options: ScanOptions = {}): Promise<string[]> {
  const resolvedRoot = options.targetPath
    ? path.resolve(options.cwd ?? process.cwd(), options.targetPath)
    : (options.cwd ?? process.cwd());
  const rootStats = await safeStat(resolvedRoot);
  const cwd = rootStats?.isDirectory() ? resolvedRoot : path.dirname(resolvedRoot);
  const targetFile = rootStats?.isFile() ? resolvedRoot : undefined;
  const { filters } = await resolveScanContext(options, cwd, targetFile);
  return walkFiles(cwd, filters);
}

async function resolveScanContext(options: ScanOptions, cwd: string, targetFile?: string) {
  const globalConfig = await loadGlobalConfig();
  const projectConfig = await loadProjectConfig(cwd);
  const baseFilters = resolveProjectFilters({
    include: options.include ?? projectConfig.include,
    exclude: options.exclude ?? projectConfig.exclude
  });
  const filters = targetFile
    ? {
        include: [path.relative(cwd, targetFile).split(path.sep).join("/")],
        exclude: []
      }
    : baseFilters;
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

export function chunkCodeByBoundary(code: string, ast: import("@babel/types").File, maxChars: number): string[] {
  const segments: Array<{ start: number; end: number }> = [];
  const functionSegments = collectFunctionSegments(ast);

  const body = ast.program.body ?? [];
  for (const node of body) {
    const range = getNodeRange(node);
    if (!range) continue;
    if (functionSegments.some((seg) => isRangeInside(range, seg))) continue;
    segments.push(range);
  }

  segments.push(...functionSegments);
  segments.sort((a, b) => a.start - b.start);

  if (!segments.length) {
    return chunkText(code, maxChars);
  }

  const chunks: string[] = [];
  for (const seg of segments) {
    const slice = code.slice(seg.start, seg.end);
    if (slice.length <= maxChars) {
      chunks.push(slice);
    } else {
      chunks.push(...chunkText(slice, maxChars));
    }
  }

  return chunks.length ? chunks : chunkText(code, maxChars);
}

function collectFunctionSegments(ast: import("@babel/types").File): Array<{ start: number; end: number }> {
  const traverse = normalizeTraverse(traverseImport);
  const segments: Array<{ start: number; end: number }> = [];
  let functionDepth = 0;

  traverse(ast, {
    Function: {
      enter(path) {
        if (functionDepth === 0) {
          const inClass = Boolean(
            path.findParent((parent) => parent.isClassDeclaration() || parent.isClassExpression())
          );
          if (!inClass) {
            const range = getFunctionRange(path);
            if (range) segments.push(range);
          }
        }
        functionDepth += 1;
      },
      exit() {
        functionDepth = Math.max(0, functionDepth - 1);
      }
    }
  });

  return segments;
}

function getFunctionRange(
  path: import("@babel/traverse").NodePath
): { start: number; end: number } | null {
  const node = path.node as any;
  if (path.isFunctionDeclaration() || path.isObjectMethod() || path.isClassMethod() || path.isClassPrivateMethod()) {
    return getNodeRange(node);
  }
  const stmt = path.getStatementParent();
  if (stmt) {
    const range = getNodeRange(stmt.node);
    if (range) return range;
  }
  return getNodeRange(node);
}

function getNodeRange(node: any): { start: number; end: number } | null {
  const start = node?.start;
  const end = node?.end;
  if (typeof start !== "number" || typeof end !== "number" || end <= start) return null;
  return { start, end };
}

function isRangeInside(inner: { start: number; end: number }, outer: { start: number; end: number }): boolean {
  return inner.start >= outer.start && inner.end <= outer.end;
}

function buildPrompt(filePath: string, chunk: string, index: number, total: number): string {
  return buildPromptWithContext(filePath, chunk, index, total);
}

export function buildPromptWithContext(
  filePath: string,
  chunk: string,
  index: number,
  total: number,
  context?: string
): string {
  const contextBlock = context
    ? [`Context Summary:`, context.trim(), ``]
    : [];
  return [
    "You are a security static analysis engine.",
    "Return JSON only.",
    "Do not add explanations.",
    "Do not wrap in markdown.",
    "Do not add code fences.",
    "",
    ...contextBlock,
    "Schema:",
    "{\"findings\":[{\"id\":string,\"severity\":\"low|medium|high|critical\",\"title\":string,\"description\":string,\"file\":string,\"line\":number}]}",
    "",
    `Analyze this code chunk from ${filePath} (chunk ${index}/${total}):`,
    chunk
  ].join("\n");
}

type CallModelParams = {
  provider: Provider;
  apiKey: string;
  baseUrl?: string;
  apiType?: "responses" | "chat";
  model: string;
  prompt: string;
};

type CodexCliParams = {
  prompt: string;
  onOutputChunk?: (chunk: string) => void;
};

async function resolveProviderAuthToken(globalConfig: {
  apiKey?: string;
  authMode?: "oauth" | "api_key";
  authProfileId?: string;
  provider?: Provider;
  providerApiKey?: string;
}, provider: Provider): Promise<string | undefined> {
  if (provider !== "openai") {
    return resolveNonOpenAiApiKey(globalConfig, provider);
  }

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

function resolveNonOpenAiApiKey(
  globalConfig: { providerApiKey?: string; apiKey?: string },
  provider: Provider
): string | undefined {
  const envKey = getProviderEnvKey(provider);
  return (
    globalConfig.providerApiKey?.trim() ||
    process.env[envKey]?.trim() ||
    globalConfig.apiKey?.trim()
  );
}

function getProviderEnvKey(provider: Provider): string {
  switch (provider) {
    case "anthropic":
      return "ANTHROPIC_API_KEY";
    case "google":
      return "GEMINI_API_KEY";
    case "mistral":
      return "MISTRAL_API_KEY";
    case "xai":
      return "XAI_API_KEY";
    case "cohere":
      return "COHERE_API_KEY";
    case "openai":
    default:
      return "OPENAI_API_KEY";
  }
}

async function callCodexCli(params: CodexCliParams): Promise<string> {
  const { prompt, onOutputChunk } = params;
  const { spawn } = await import("node:child_process");

  return new Promise((resolve, reject) => {
    const args = [
      "exec",
      "--skip-git-repo-check",
      "--sandbox",
      "read-only"
    ];

    const child = spawn("codex", [...args, prompt], {
      stdio: ["ignore", "pipe", "ignore"]
    });

    let stdout = "";
    child.stdout.on("data", (chunk) => {
      const text = chunk.toString();
      stdout += text;
      if (onOutputChunk) onOutputChunk(text);
    });

    child.on("error", (err) => reject(new Error(`codex exec failed: ${err.message}`)));
    child.on("close", (code) => {
      if (code && code !== 0) {
        reject(new Error(`codex exec failed with exit code ${code}`));
        return;
      }
      resolve(stdout);
    });
  });
}

async function callCodexCliWithRetry(
  prompt: string,
  maxRetries: number,
  retryDelayMs: number,
  onOutputChunk?: (chunk: string) => void
): Promise<ScanResult> {
  let attempt = 0;
  let delay = retryDelayMs;
  while (true) {
    try {
      const output = await callCodexCli({ prompt, onOutputChunk });
      const parsed = extractJson(output);
      if (!parsed) {
        throw new Error("Codex returned non-JSON output.");
      }
      return parsed;
    } catch (err) {
      if (attempt >= maxRetries) throw err;
      await sleep(delay + Math.floor(Math.random() * 100));
      delay = Math.max(delay * 2, retryDelayMs);
      attempt += 1;
    }
  }
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
  const { provider } = params;
  switch (provider) {
    case "openai":
      return callOpenAiModel(params);
    case "anthropic":
      return callAnthropicModel(params);
    case "google":
      return callGeminiModel(params);
    case "mistral":
      return callMistralModel(params);
    case "xai":
      return callXaiModel(params);
    case "cohere":
      return callCohereModel(params);
    default:
      throw new Error(`Unsupported provider: ${provider}`);
  }
}

async function callOpenAiModel(params: CallModelParams): Promise<string> {
  const { apiKey, baseUrl, apiType, model, prompt } = params;
  if (!baseUrl || !apiType) {
    throw new Error("OpenAI baseUrl and apiType are required.");
  }
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

async function callAnthropicModel(params: CallModelParams): Promise<string> {
  const { apiKey, baseUrl, model, prompt } = params;
  const url = baseUrl ?? "https://api.anthropic.com/v1/messages";
  const body = JSON.stringify({
    model,
    max_tokens: 1024,
    messages: [{ role: "user", content: prompt }]
  });
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01"
    },
    body
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Anthropic request failed: ${res.status} ${text}`);
  }
  const data = await res.json();
  return data?.content?.[0]?.text ?? "";
}

async function callGeminiModel(params: CallModelParams): Promise<string> {
  const { apiKey, baseUrl, model, prompt } = params;
  const base = baseUrl ?? "https://generativelanguage.googleapis.com/v1beta/models";
  const modelPath = model.startsWith("models/") ? model.slice("models/".length) : model;
  const url = `${base}/${modelPath}:generateContent`;
  const body = JSON.stringify({
    contents: [{ role: "user", parts: [{ text: prompt }] }]
  });
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-goog-api-key": apiKey },
    body
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Gemini request failed: ${res.status} ${text}`);
  }
  const data = await res.json();
  const parts = data?.candidates?.[0]?.content?.parts ?? [];
  return parts.map((p: any) => p?.text ?? "").join("");
}

async function callMistralModel(params: CallModelParams): Promise<string> {
  const { apiKey, baseUrl, model, prompt } = params;
  const url = baseUrl ?? "https://api.mistral.ai/v1/chat/completions";
  const body = JSON.stringify({
    model,
    messages: [{ role: "user", content: prompt }],
    temperature: 0
  });
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`
    },
    body
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Mistral request failed: ${res.status} ${text}`);
  }
  const data = await res.json();
  return data?.choices?.[0]?.message?.content ?? "";
}

async function callXaiModel(params: CallModelParams): Promise<string> {
  const { apiKey, baseUrl, model, prompt } = params;
  const url = baseUrl ?? "https://api.x.ai/v1/chat/completions";
  const body = JSON.stringify({
    model,
    messages: [{ role: "user", content: prompt }],
    temperature: 0
  });
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`
    },
    body
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`xAI request failed: ${res.status} ${text}`);
  }
  const data = await res.json();
  return data?.choices?.[0]?.message?.content ?? "";
}

async function callCohereModel(params: CallModelParams): Promise<string> {
  const { apiKey, baseUrl, model, prompt } = params;
  const url = baseUrl ?? "https://api.cohere.com/v2/chat";
  const body = JSON.stringify({
    model,
    messages: [{ role: "user", content: prompt }],
    temperature: 0
  });
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`
    },
    body
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Cohere request failed: ${res.status} ${text}`);
  }
  const data = await res.json();
  return data?.message?.content?.[0]?.text ?? "";
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
      const location = item.line
        ? item.column
          ? `${item.file}:${item.line}:${item.column}`
          : `${item.file}:${item.line}`
        : item.file;
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
  return JSON.stringify({ schemaVersion: SCHEMA_VERSION, ...result }, null, 2);
}

export function renderSarifReport(result: ScanResult): string {
  const sarifResults = result.findings.map((finding) => {
    const level = mapSeverityToSarif(finding.severity);
    const message = [finding.title, finding.description].filter(Boolean).join(" — ");
    const location: any = {
      physicalLocation: {
        artifactLocation: { uri: finding.file }
      }
    };
    if (finding.line) {
      location.physicalLocation.region = {
        startLine: finding.line,
        ...(finding.column ? { startColumn: finding.column } : {})
      };
    }
    return {
      ruleId: finding.id,
      level,
      message: { text: message },
      locations: [location]
    };
  });

  const sarif = {
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "OpenSecurity", version: SCHEMA_VERSION } },
        results: sarifResults
      }
    ]
  };

  return JSON.stringify(sarif, null, 2);
}

function isAnalyzableFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  // JS/TS only: Babel AST parser expects JS/TS syntax.
  const supported = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"];
  return supported.includes(ext);
}

function isLikelyTextFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  if (!ext) return true;
  const blocked = new Set([
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".svg",
    ".zip", ".gz", ".tgz", ".rar", ".7z",
    ".pdf", ".mp3", ".mp4", ".mov", ".avi", ".mkv",
    ".woff", ".woff2", ".ttf", ".otf",
    ".bin", ".exe", ".dmg", ".iso"
  ]);
  return !blocked.has(ext);
}

type FileBatch = { key: string; files: string[] };

export function groupFilesByModule(relPaths: string[], depth: number): Map<string, string[]> {
  const groups = new Map<string, string[]>();
  for (const relPath of relPaths) {
    const normalized = relPath.split(path.sep).join("/");
    const parts = normalized.split("/");
    const last = parts[parts.length - 1] ?? "";
    const isFile = last.includes(".");
    const dirParts = isFile ? parts.slice(0, -1) : parts;
    let key = "root";
    if (dirParts[0] === "src" && dirParts.length > 1) {
      key = ["src", ...dirParts.slice(1, 1 + depth)].join("/");
    } else if (dirParts[0] === "packages" && dirParts.length > 1) {
      key = ["packages", dirParts[1]].join("/");
    } else if (dirParts[0] === "apps" && dirParts.length > 1) {
      key = ["apps", dirParts[1]].join("/");
    } else if (dirParts.length > 1) {
      key = dirParts[0];
    }
    const bucket = groups.get(key) ?? [];
    bucket.push(normalized);
    groups.set(key, bucket);
  }
  return groups;
}

export function createBatches(groups: Map<string, string[]>, batchSize: number): FileBatch[] {
  const batches: FileBatch[] = [];
  for (const [key, files] of groups.entries()) {
    for (let i = 0; i < files.length; i += batchSize) {
      batches.push({ key, files: files.slice(i, i + batchSize) });
    }
  }
  return batches;
}

type CachedAiEntry = { hash: string; findings: Finding[] };

function resolveCachePath(cwd: string, override?: string): string {
  if (override && override.trim()) {
    return path.isAbsolute(override) ? override : path.join(cwd, override);
  }
  return path.join(cwd, ".opensecurity", "ai-cache.json");
}

async function loadAiCache(cachePath: string): Promise<{ entries: Map<string, CachedAiEntry> }> {
  try {
    const raw = await fs.readFile(cachePath, "utf8");
    const parsed = JSON.parse(raw) as Record<string, CachedAiEntry>;
    const entries = new Map<string, CachedAiEntry>(Object.entries(parsed ?? {}));
    return { entries };
  } catch (err: any) {
    if (err?.code === "ENOENT") return { entries: new Map() };
    return { entries: new Map() };
  }
}

async function saveAiCache(cachePath: string, cache: { entries: Map<string, CachedAiEntry> }): Promise<void> {
  const obj: Record<string, CachedAiEntry> = {};
  for (const [key, value] of cache.entries.entries()) {
    obj[key] = value;
  }
  await fs.mkdir(path.dirname(cachePath), { recursive: true });
  await fs.writeFile(cachePath, JSON.stringify(obj, null, 2), "utf8");
}

function computeCacheKey(provider: Provider, model: string, content: string): string {
  return crypto
    .createHash("sha256")
    .update(provider)
    .update("|")
    .update(model)
    .update("|")
    .update(content)
    .digest("hex");
}

async function safeStat(target: string): Promise<import("node:fs").Stats | null> {
  try {
    return await fs.stat(target);
  } catch {
    return null;
  }
}

const execFileAsync = promisify(execFile);

async function getChangedFiles(cwd: string, baseRef: string): Promise<string[]> {
  try {
    const [diff, diffCached, diffBase, untracked] = await Promise.all([
      execFileAsync("git", ["-C", cwd, "diff", "--name-only", "--diff-filter=ACMR"], { encoding: "utf8" }),
      execFileAsync("git", ["-C", cwd, "diff", "--name-only", "--diff-filter=ACMR", "--cached"], { encoding: "utf8" }),
      execFileAsync("git", ["-C", cwd, "diff", "--name-only", "--diff-filter=ACMR", baseRef], { encoding: "utf8" }),
      execFileAsync("git", ["-C", cwd, "ls-files", "--others", "--exclude-standard"], { encoding: "utf8" })
    ]);

    const entries = [diff.stdout, diffCached.stdout, diffBase.stdout, untracked.stdout]
      .join("\n")
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);

    return Array.from(new Set(entries));
  } catch (err: any) {
    throw new Error("diff-only requires a git repository with a valid base ref.");
  }
}

async function buildLeaderContext(cwd: string): Promise<string> {
  const parts: string[] = [];
  const readIfExists = async (filePath: string) => {
    try {
      return await fs.readFile(filePath, "utf8");
    } catch {
      return "";
    }
  };

  const readme = await readIfExists(path.join(cwd, "README.md"));
  if (readme) {
    parts.push("README:", truncateLines(readme, 12));
  }

  const pkgRaw = await readIfExists(path.join(cwd, "package.json"));
  if (pkgRaw) {
    try {
      const pkg = JSON.parse(pkgRaw) as { name?: string; version?: string; description?: string };
      parts.push(`package.json: ${[pkg.name, pkg.version, pkg.description].filter(Boolean).join(" | ")}`);
    } catch {
      parts.push("package.json: (unreadable)");
    }
  }

  try {
    const entries = await fs.readdir(cwd, { withFileTypes: true });
    const top = entries
      .filter((e) => ![".git", "node_modules", "dist", "build", "coverage"].includes(e.name))
      .map((e) => (e.isDirectory() ? `${e.name}/` : e.name))
      .slice(0, 30);
    if (top.length) {
      parts.push(`Top-level: ${top.join(", ")}`);
    }
  } catch {
    // ignore
  }

  return parts.join("\n");
}

function truncateLines(text: string, maxLines: number): string {
  const lines = text.split(/\r?\n/).filter((line) => line.trim().length);
  return lines.slice(0, maxLines).join("\n");
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Map<string, Finding>();
  for (const finding of findings) {
    const line = finding.line ?? 0;
    const key = `${finding.file}:${line}:${finding.id}`;
    if (!seen.has(key)) {
      seen.set(key, finding);
    }
  }
  return Array.from(seen.values());
}

function mapSeverityToSarif(severity: Severity): "error" | "warning" | "note" {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "note";
    default:
      return "note";
  }
}

function normalizeTraverse(
  value: typeof traverseImport
): typeof traverseImport {
  return (value as unknown as { default?: typeof traverseImport }).default ?? value;
}
