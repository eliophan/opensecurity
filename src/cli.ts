#!/usr/bin/env node
import { Command } from "commander";
import { login } from "./login.js";
import { scan, renderJsonReport, renderTextReport } from "./scan.js";

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
  .action(async (opts) => {
    try {
      const result = await scan({
        format: opts.format,
        maxChars: opts.maxChars,
        model: opts.model
      });
      const output = opts.format === "json" ? renderJsonReport(result) : renderTextReport(result);
      console.log(output || "No findings.");
    } catch (err: any) {
      console.error(err?.message ?? err);
      process.exitCode = 1;
    }
  });

program.parse();
