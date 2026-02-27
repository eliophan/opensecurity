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
  const apiKey = env.OPENAI_API_KEY?.trim() || (await prompt("Enter OPENAI_API_KEY: "));
  if (!apiKey) {
    throw new Error("OPENAI_API_KEY is required to login.");
  }
  const updated: GlobalConfig = { ...current, apiKey };
  await saveGlobalConfig(updated, env);
  return updated;
}
