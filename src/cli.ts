#!/usr/bin/env node
import path from "node:path";
import { Command } from "commander";
import { login } from "./login.js";
import { scan, renderJsonReport, renderTextReport, listMatchedFiles } from "./scan.js";

const program = new Command();

program
  .name("opensecurity")
  .description("openSecurity CLI")
  .version("0.1.0");

program
  .command("login")
  .description("Store OpenAI API key in global config")
  .action(async () => {
    try {
      await login();
      console.log("Saved API key to global config.");
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
  .option("--dry-run", "list matched files without calling the model")
  .action(async (opts) => {
    try {
      if (opts.dryRun) {
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
        console.log(output);
        return;
      }

      const result = await scan({
        format: opts.format,
        maxChars: opts.maxChars,
        model: opts.model,
        cwd: opts.cwd,
        include: opts.include,
        exclude: opts.exclude,
        rulesPath: opts.rules,
        cveCachePath: opts.cveCache,
        cveApiUrl: opts.cveApiUrl,
        simulate: opts.simulate,
        dataSensitivity: opts.dataSensitivity
      });
      const output = opts.format === "json" ? renderJsonReport(result) : renderTextReport(result);
      console.log(output || "No findings.");
    } catch (err: any) {
      console.error(err?.message ?? err);
      process.exitCode = 1;
    }
  });

program.parse();
