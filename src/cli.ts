#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import { Command } from "commander";
import { login } from "./login.js";
import { startProxyServer } from "./proxy.js";
import { scan, renderJsonReport, renderSarifReport, renderTextReport, listMatchedFiles } from "./scan.js";
import { setTelemetryEnabled, trackEvent } from "./telemetry.js";
import { loadGlobalConfig } from "./config.js";
import { getOAuthProfile } from "./oauthStore.js";
import { Logger, Spinner, formatDuration, pluralize, bold, severityColor } from "./progress.js";

const program = new Command();

program
  .name("opensecurity")
  .description("openSecurity CLI")
  .version("0.1.0");

program
  .command("login")
  .description("Store Codex Access Token in global config")
  .option("--mode <mode>", "oauth|api_key")
  .option("--provider <provider>", "openai|anthropic|google|mistral|xai|cohere")
  .option("--model <model>", "set default model")
  .action(async (opts) => {
    try {
      await login(process.env, opts.mode, opts.model, opts.provider);
    } catch (err: any) {
      console.error(err?.message ?? err);
      process.exitCode = 1;
    }
  });

program
  .command("proxy")
  .description("Run local OAuth proxy for Codex tokens")
  .option("--port <port>", "port to listen on", (v) => Number(v), 8787)
  .action(async (opts) => {
    try {
      await startProxyServer({ port: opts.port });
    } catch (err: any) {
      console.error(err?.message ?? err);
      process.exitCode = 1;
    }
  });

program
  .command("scan")
  .description("Run AI security scan")
  .option("--format <format>", "text|json|sarif", "text")
  .option("--max-chars <maxChars>", "max chars per chunk", (v) => Number(v), 4000)
  .option("--model <model>", "override model")
  .option("--auth <mode>", "oauth|api_key (overrides config)", (value) => {
    if (value !== "oauth" && value !== "api_key") {
      throw new Error("--auth must be 'oauth' or 'api_key'");
    }
    return value;
  })
  .option("--provider <provider>", "openai|anthropic|google|mistral|xai|cohere")
  .option("--cwd <cwd>", "override working directory")
  .option("--include <pattern...>", "include glob patterns (overrides project config)")
  .option("--exclude <pattern...>", "exclude glob patterns (overrides project config)")
  .option("--rules <path>", "path to rules JSON (overrides project config)")
  .option("--cve-cache <path>", "path to CVE cache JSON (overrides project config)")
  .option("--cve-api-url <url>", "CVE API URL (overrides project config)")
  .option("--simulate", "include simulated payload + impact for dependency findings")
  .option(
    "--data-sensitivity <level>",
    "low|medium|high (affects risk scoring)",
    "medium"
  )
  .option("--ai-all-text", "allow AI scan on all text files (non-JS/TS)")
  .option("--ai-js-only", "limit AI scan to JS/TS only")
  .option("--concurrency <n>", "parallel scan workers", (v) => Number(v))
  .option("--dependency-only", "only run dependency/CVE scanning")
  .option("--no-ai", "skip AI model scanning")
  .option("--diff-only", "only scan files changed in git")
  .option("--diff-base <ref>", "git base ref for diff-only (default: HEAD)")
  .option("--dry-run", "list matched files without calling the model")
  .option("--fail-on <severity>", "fail if findings are >= severity (low|medium|high|critical)")
  .option("--fail-on-high", "fail if findings are >= high")
  .option("--sarif-output <path>", "write SARIF to file in addition to primary output")
  .option("--verbose", "show detailed progress information")
  .action(async (opts) => {
    await executeScan(opts);
  });

async function executeScan(opts: any) {
  const isJson = opts.format === "json";
  const log = new Logger({ verbose: opts.verbose, silent: isJson });

  try {
    const authMode = await resolveAuthMode(opts);
    if (authMode) {
      opts.auth = authMode;
    }
    if (opts.dryRun) {
      log.info("Dry run — listing matched files…");
      const files = await listMatchedFiles({
        cwd: opts.cwd,
        include: opts.include,
        exclude: opts.exclude
      });
      if (!files.length) {
        console.log("No files matched.");
        return;
      }
      const base = opts.cwd ?? process.cwd();
      const output = files.map((file: string) => path.relative(base, file)).join("\n");
      log.info(`Found ${pluralize(files.length, "file")}.`);
      console.log(output);
      return;
    }

    const startTime = Date.now();
    const cwd = opts.cwd ?? process.cwd();

    log.info(`Scanning ${bold(cwd)}…`);
    log.verbose(`Format: ${opts.format}, Model: ${opts.model ?? "default"}`);
    log.verbose(`AI scanning: ${opts.noAi ? "disabled" : "enabled"}`);
    log.verbose(`Dependency-only: ${opts.dependencyOnly ? "yes" : "no"}`);

    const liveOutput = Boolean(opts.verbose);
    const spinner = new Spinner("Running security scan…");
    const useSpinner = !isJson;
    if (useSpinner) spinner.start();

    const result = await scan({
      format: opts.format,
      maxChars: opts.maxChars,
      model: opts.model,
      authMode: opts.auth,
      provider: opts.provider,
      liveOutput,
      onProgress: (info) => {
        const message = `Scanning ${info.file} (${info.fileIndex}/${info.totalFiles}) chunk ${info.chunkIndex}/${info.totalChunks}`;
        if (useSpinner) {
          spinner.update(message);
        }
        if (opts.verbose) {
          log.verbose(message);
        }
      },
      onOutputChunk: liveOutput && !isJson ? (chunk) => {
        if (useSpinner) spinner.pause();
        process.stderr.write(chunk);
        if (useSpinner) spinner.resume();
      } : undefined,
      cwd: opts.cwd,
      include: opts.include,
      exclude: opts.exclude,
      rulesPath: opts.rules,
      cveCachePath: opts.cveCache,
      cveApiUrl: opts.cveApiUrl,
      simulate: opts.simulate,
      dataSensitivity: opts.dataSensitivity,
      dependencyOnly: opts.dependencyOnly,
      noAi: opts.noAi,
      aiAllText: opts.aiJsOnly ? false : (opts.aiAllText ?? true),
      diffOnly: opts.diffOnly,
      diffBase: opts.diffBase,
      concurrency: opts.concurrency
    });

    const elapsed = Date.now() - startTime;
    if (useSpinner) spinner.stop();

    const output =
      opts.format === "sarif"
        ? renderSarifReport(result)
        : isJson
          ? renderJsonReport(result)
          : renderTextReport(result);
    console.log(output || "No findings.");

    if (opts.sarifOutput && opts.format !== "sarif") {
      const sarif = renderSarifReport(result);
      await fs.writeFile(opts.sarifOutput, sarif, "utf8");
    }

    // Print summary
    if (!isJson) {
      const total = result.findings.length;
      if (total === 0) {
        log.success(`Scan complete in ${formatDuration(elapsed)} — no findings.`);
      } else {
        const counts = countBySeverity(result.findings);
        const parts: string[] = [];
        for (const [sev, count] of Object.entries(counts)) {
          if (count > 0) parts.push(`${severityColor(sev)}: ${count}`);
        }
        log.warn(
          `Scan complete in ${formatDuration(elapsed)} — ${pluralize(total, "finding")} [${parts.join(", ")}]`
        );
      }
    }

    if (opts.failOn) {
      const threshold = severityRank(opts.failOn);
      if (threshold === null) {
        log.warn(`Unknown --fail-on level: ${opts.failOn}`);
      } else {
        const worst = highestSeverity(result.findings);
        if (worst !== null && worst >= threshold) {
          process.exitCode = 1;
        }
      }
    }
    if (opts.failOnHigh) {
      const threshold = severityRank("high");
      const worst = highestSeverity(result.findings);
      if (worst !== null && threshold !== null && worst >= threshold) {
        process.exitCode = 1;
      }
    }

    // Fire telemetry event (no-ops if disabled)
    const globalCfg = await loadGlobalConfig();
    await trackEvent("scan_completed", {
      findings: result.findings.length,
      format: opts.format ?? "text",
      dependencyOnly: Boolean(opts.dependencyOnly),
      noAi: Boolean(opts.noAi)
    }, globalCfg);
  } catch (err: any) {
    log.error(err?.message ?? err);
    process.exitCode = 1;
  }
}

program
  .command("telemetry")
  .description("Enable or disable anonymous telemetry")
  .argument("<action>", "on | off")
  .action(async (action: string) => {
    try {
      const enabled = action.toLowerCase() === "on";
      await setTelemetryEnabled(enabled);
      console.log(`Telemetry ${enabled ? "enabled" : "disabled"}.`);
    } catch (err: any) {
      console.error(err?.message ?? err);
      process.exitCode = 1;
    }
  });

program.parse();

// --- helpers ---

function countBySeverity(findings: Array<{ severity: string }>): Record<string, number> {
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  }
  return counts;
}

function severityRank(severity: string): number | null {
  switch (severity) {
    case "critical":
      return 3;
    case "high":
      return 2;
    case "medium":
      return 1;
    case "low":
      return 0;
    default:
      return null;
  }
}

function highestSeverity(findings: Array<{ severity: string }>): number | null {
  let max: number | null = null;
  for (const f of findings) {
    const rank = severityRank(f.severity);
    if (rank === null) continue;
    if (max === null || rank > max) max = rank;
  }
  return max;
}

async function resolveAuthMode(opts: any): Promise<"oauth" | "api_key" | undefined> {
  if (opts.auth) return opts.auth;
  const globalCfg = await loadGlobalConfig();
  const hasApiKey = Boolean(globalCfg.apiKey);
  const profileId = globalCfg.authProfileId ?? "codex-cli";
  const oauthProfile = await getOAuthProfile(profileId);
  const hasOauth = Boolean(oauthProfile);

  if (hasApiKey && hasOauth) {
    return await promptAuthMode();
  }

  if (hasOauth) return "oauth";
  if (hasApiKey) return "api_key";
  return undefined;
}

async function promptAuthMode(): Promise<"oauth" | "api_key"> {
  try {
    return await interactiveSelectAuth();
  } catch {
    // fall through to text prompt
  }
  const answer = await askQuestion("Select auth mode for this scan (oauth/api_key): ");
  return answer.trim() === "api_key" ? "api_key" : "oauth";
}

function askQuestion(question: string): Promise<string> {
  const readline = require("node:readline");
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer: string) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

async function interactiveSelectAuth(): Promise<"oauth" | "api_key"> {
  return new Promise((resolve, reject) => {
    const readline = require("node:readline");
    const { input, output, cleanup: baseCleanup } = getInteractiveStreams();
    readline.emitKeypressEvents(input);
    input.setRawMode(true);

    const options: Array<{ label: string; value: "oauth" | "api_key" }> = [
      { label: "OpenAI Codex OAuth", value: "oauth" },
      { label: "OpenAI API Key", value: "api_key" }
    ];
    let index = 0;

    const render = () => {
      output.write("\x1b[2J\x1b[H");
      output.write("Select auth mode for this scan\n");
      for (let i = 0; i < options.length; i += 1) {
        const prefix = i === index ? "◉" : "○";
        output.write(`${prefix} ${options[i].label}\n`);
      }
      output.write("\nUse ↑/↓ to move, Enter to select.\n");
    };

    const cleanup = () => {
      input.off("keypress", onKeypress as any);
      baseCleanup();
    };

    const onKeypress = (_: string, key: { name?: string; ctrl?: boolean }) => {
      if (key.ctrl && key.name === "c") {
        cleanup();
        reject(new Error("Selection cancelled."));
        return;
      }
      if (key.name === "down") {
        index = (index + 1) % options.length;
        render();
        return;
      }
      if (key.name === "up") {
        index = (index - 1 + options.length) % options.length;
        render();
        return;
      }
      if (key.name === "return") {
        const value = options[index].value;
        cleanup();
        resolve(value);
      }
    };

    input.on("keypress", onKeypress as any);
    render();
  });
}

function shouldForceInteractive(): boolean {
  return process.env.OPENSECURITY_FORCE_TTY === "1";
}

function getInteractiveStreams(): {
  input: any;
  output: any;
  cleanup: () => void;
} {
  if (process.stdin.isTTY && process.stdout.isTTY) {
    const wasRaw = process.stdin.isRaw;
    const cleanup = () => {
      if (!wasRaw) process.stdin.setRawMode(false);
      process.stdout.write("\x1b[2J\x1b[H");
    };
    return { input: process.stdin, output: process.stdout, cleanup };
  }
  try {
    const tty = require("node:tty");
    const fs = require("node:fs");
    const fd = fs.openSync("/dev/tty", "r+");
    const input = new tty.ReadStream(fd);
    const output = new tty.WriteStream(fd);
    const cleanup = () => {
      input.setRawMode(false);
      input.pause();
      output.write("\x1b[2J\x1b[H");
      fs.closeSync(fd);
    };
    return { input, output, cleanup };
  } catch {
    throw new Error("No TTY available for interactive selection.");
  }
}
