import readline from "node:readline";
import { loadGlobalConfig, saveGlobalConfig, type GlobalConfig } from "./config.js";

export type PromptFn = (question: string) => Promise<string>;

export function defaultPrompt(question: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

export async function login(
  env = process.env,
  prompt: PromptFn = defaultPrompt
): Promise<GlobalConfig> {
  const current = await loadGlobalConfig(env);

  if (env.CODEX_API_KEY || env.OPENAI_API_KEY) {
    const apiKey = (env.CODEX_API_KEY || env.OPENAI_API_KEY)!.trim();
    const updated: GlobalConfig = { ...current, apiKey };
    await saveGlobalConfig(updated, env);
    return updated;
  }

  console.log("Welcome to OpenSecurity! We use Codex for AI static analysis.");
  console.log("To authenticate, please visit:");
  console.log("\n  https://auth.codex.example.com/login?client=opensecurity\n");
  console.log("Copy the provided access token and paste it below.");

  const rawToken = await prompt("Codex Access Token: ");
  const apiKey = rawToken.trim();

  if (!apiKey) {
    throw new Error("Codex Access Token is required to login.");
  }

  const updated: GlobalConfig = { ...current, apiKey };
  await saveGlobalConfig(updated, env);
  return updated;
}
