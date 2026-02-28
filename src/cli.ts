#!/usr/bin/env node
import path from "node:path";
import { Command } from "commander";
import { login } from "./login.js";
import { startProxyServer } from "./proxy.js";
import { scan, renderJsonReport, renderTextReport, listMatchedFiles } from "./scan.js";
import { setTelemetryEnabled, trackEvent } from "./telemetry.js";
import { loadGlobalConfig } from "./config.js";
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
  .option("--model <model>", "set default model")
  .action(async (opts) => {
    try {
      await login(process.env, opts.mode, opts.model);
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
  .option("--format <format>", "text|json", "text")
  .option("--max-chars <maxChars>", "max chars per chunk", (v) => Number(v), 4000)
  .option("--model <model>", "override model")
  .option("--auth <mode>", "oauth|api_key (overrides config)")
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
  .option("--dependency-only", "only run dependency/CVE scanning")
  .option("--no-ai", "skip AI model scanning")
  .option("--dry-run", "list matched files without calling the model")
  .option("--verbose", "show detailed progress information")
  .action(async (opts) => {
    await executeScan(opts);
  });

async function executeScan(opts: any) {
  const isJson = opts.format === "json";
  const log = new Logger({ verbose: opts.verbose, silent: isJson });

  try {
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
    const useSpinner = !isJson && !liveOutput;
    if (useSpinner) spinner.start();

    const result = await scan({
      format: opts.format,
      maxChars: opts.maxChars,
      model: opts.model,
      authMode: opts.auth,
      liveOutput,
      onProgress: (info) => {
        const message = `Scanning ${info.file} (${info.fileIndex}/${info.totalFiles}) chunk ${info.chunkIndex}/${info.totalChunks}`;
        if (useSpinner) {
          spinner.update(message);
        } else if (opts.verbose) {
          log.verbose(message);
        }
      },
      onOutputChunk: liveOutput && !isJson ? (chunk) => process.stderr.write(chunk) : undefined,
      cwd: opts.cwd,
      include: opts.include,
      exclude: opts.exclude,
      rulesPath: opts.rules,
      cveCachePath: opts.cveCache,
      cveApiUrl: opts.cveApiUrl,
      simulate: opts.simulate,
      dataSensitivity: opts.dataSensitivity,
      dependencyOnly: opts.dependencyOnly,
      noAi: opts.noAi
    });

    const elapsed = Date.now() - startTime;
    if (useSpinner) spinner.stop();

    const output = isJson ? renderJsonReport(result) : renderTextReport(result);
    console.log(output || "No findings.");

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
