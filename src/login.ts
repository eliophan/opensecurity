import readline from "node:readline";
import http from "node:http";
import crypto from "node:crypto";
import { exec, spawn } from "node:child_process";
import { loadGlobalConfig, saveGlobalConfig, type GlobalConfig, type Provider } from "./config.js";
import { saveOAuthProfile } from "./oauthStore.js";

export function askQuestion(question: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

// For unit tests
export async function saveMockToken(token: string, env = process.env): Promise<GlobalConfig> {
  const current = await loadGlobalConfig(env);
  const updated: GlobalConfig = { ...current, apiKey: token };
  await saveGlobalConfig(updated, env);
  return updated;
}

type LoginMode = "oauth" | "api_key";

export async function login(
  env = process.env,
  mode?: LoginMode,
  model?: string,
  provider?: Provider
): Promise<GlobalConfig> {
  console.log("\n\x1b[32m\u25C7\x1b[0m  \x1b[1mOpenSecurity Authentication\x1b[0m");
  if (mode === "api_key") {
    return loginWithApiKey(env, model, provider);
  }
  if (mode === "oauth") {
    if (provider && provider !== "openai") {
      throw new Error("OAuth is only supported for OpenAI.");
    }
    return loginWithOAuth(env, model);
  }
  const modeChoice = await promptLoginMode();
  if (modeChoice === "api_key") {
    return loginWithApiKey(env, model, provider);
  }
  // Option 1: Codex OAuth (Default)
  return loginWithOAuth(env, model);
}

async function loginWithApiKey(
  env = process.env,
  model?: string,
  provider?: Provider
): Promise<GlobalConfig> {
  const current = await loadGlobalConfig(env);
  const selectedProvider = provider ?? (await chooseProvider(current.provider ?? "openai"));
  const key = await askQuestion(`Enter your ${providerLabel(selectedProvider)} API Key: `);

  if (selectedProvider === "openai" && !key.startsWith("sk-")) {
    console.error("\x1b[31mError: Invalid OpenAI API key format.\x1b[0m");
    process.exit(1);
  }

  const selectedModel = await chooseModel({
    current: model ?? current.model,
    provider: selectedProvider,
    source: selectedProvider === "openai" ? "openai" : undefined,
    apiKey: selectedProvider === "openai" ? key : undefined
  });

  const updated: GlobalConfig = {
    ...current,
    provider: selectedProvider,
    authMode: "api_key",
    model: selectedModel ?? current.model,
    apiKey: selectedProvider === "openai" ? key : current.apiKey,
    providerApiKey: selectedProvider === "openai" ? current.providerApiKey : key
  };

  await saveGlobalConfig(updated, env);
  console.log(`\n✅ Successfully saved ${providerLabel(selectedProvider)} API Key.`);
  return updated;
}

async function loginWithOAuth(env = process.env, model?: string): Promise<GlobalConfig> {
  const provider = (env.OPENSECURITY_OAUTH_PROVIDER ?? "codex-cli") as "codex-cli" | "proxy";
  if (provider === "codex-cli") {
    return codexCliOAuthLogin(env, model);
  }
  return codexOAuthLogin(env, model);
}

async function codexCliOAuthLogin(env = process.env, model?: string): Promise<GlobalConfig> {
  await runCodexLogin();
  const current = await loadGlobalConfig(env);
  const selectedModel = await chooseModel({
    current: model ?? current.model,
    source: "codex",
    provider: "openai"
  });
  const updated: GlobalConfig = {
    ...current,
    authMode: "oauth",
    oauthProvider: "codex-cli",
    authProfileId: "codex-cli",
    model: selectedModel ?? current.model
  };
  await saveGlobalConfig(updated, env);
  console.log("\n✅ Successfully authenticated with OpenAI/Codex via codex CLI.");
  return updated;
}

async function codexOAuthLogin(env = process.env, model?: string, port = 1455): Promise<GlobalConfig> {
  const current = await loadGlobalConfig(env);

  console.log("\n\x1b[32m\u25C7\x1b[0m  \x1b[1mOpenAI Codex OAuth\x1b[0m");
  console.log("   Browser will open for OpenAI authentication.");
  console.log("   OpenAI OAuth uses localhost:1455 for the callback.\n");

  const state = crypto.randomBytes(16).toString("hex");
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

  const clientId = "app_EMoamEEZ73f0CkXaXp7hrann";
  const redirectUri = encodeURIComponent(`http://localhost:${port}/auth/callback`);
  const proxyBaseUrl = env.OPENSECURITY_PROXY_URL ?? "http://localhost:8787/v1/responses";

  const authUrl = `https://auth.openai.com/oauth/authorize?response_type=code` +
    `&client_id=${clientId}` +
    `&redirect_uri=${redirectUri}` +
    `&scope=openid+profile+email+offline_access` +
    `&code_challenge=${codeChallenge}` +
    `&code_challenge_method=S256` +
    `&state=${state}` +
    `&id_token_add_organizations=true` +
    `&codex_cli_simplified_flow=true` +
    `&originator=pi`;

  console.log(`Open: ${authUrl}\n`);

  return new Promise((resolve) => {
    const server = http.createServer(async (req, res) => {
      try {
        const url = new URL(req.url || "", `http://${req.headers.host}`);

        if (url.pathname === "/auth/callback") {
          const code = url.searchParams.get("code");
          const returnedState = url.searchParams.get("state");

          if (returnedState !== state) {
            res.writeHead(400);
            res.end("State mismatch. Security error.");
            return;
          }

          if (code) {
            res.writeHead(200, { "Content-Type": "text/html" });
            res.end(`
              <html>
                <head><title>Success</title><style>body { font-family: -apple-system, sans-serif; text-align: center; margin-top: 50px; }</style></head>
                <body>
                  <h1>✅ Authentication Successful!</h1>
                  <p>OpenSecurity has successfully authenticated via OpenAI/Codex.</p>
                  <p>You can close this window and return to your terminal.</p>
                  <script>window.close();</script>
                </body>
              </html>
            `);

            const tokens = await exchangeCodeForTokens({
              code,
              codeVerifier,
              clientId,
              redirectUri: `http://localhost:${port}/auth/callback`
            });

            if (!tokens.access_token) {
              throw new Error("OAuth token exchange did not return an access_token.");
            }

            const expiresAt = tokens.expires_in
              ? Date.now() + tokens.expires_in * 1000
              : undefined;

            await saveOAuthProfile(
              {
                provider: "codex",
                accessToken: tokens.access_token,
                refreshToken: tokens.refresh_token,
                tokenType: tokens.token_type,
                scope: tokens.scope,
                expiresAt,
                obtainedAt: Date.now()
              },
              env
            );

            const selectedModel = await chooseModel({
              current: model ?? current.model,
              source: "codex",
              provider: "openai"
            });
            const updated: GlobalConfig = {
              ...current,
              baseUrl: proxyBaseUrl,
              apiType: "responses",
              authMode: "oauth",
              authProfileId: "codex",
              oauthProvider: "proxy",
              model: selectedModel ?? current.model
            };
            await saveGlobalConfig(updated, env);

            console.log(`\n✅ Successfully authenticated with OpenAI/Codex.`);
            console.log(`   Proxy base URL set to ${proxyBaseUrl}`);

            server.close();
            resolve(updated);
          } else {
            res.writeHead(400);
            res.end("No authorization code received.");
          }
        } else {
          res.writeHead(404);
          res.end("Not Found");
        }
      } catch (err) {
        res.writeHead(500);
        res.end("Internal error");
      }
    });

    server.listen(port, () => {
      exec(`open "${authUrl}"`);
    });
  });
}

function runCodexLogin(): Promise<void> {
  return new Promise((resolve, reject) => {
    const proc = spawn("codex", ["login"], { stdio: "inherit" });
    proc.on("error", reject);
    proc.on("exit", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`codex login failed with exit code ${code ?? "unknown"}`));
    });
  });
}

async function promptLoginMode(): Promise<"oauth" | "api_key"> {
  try {
    return await interactiveSelectLoginMode();
  } catch {
    // fall through to text prompt
  }
  const answer = await askQuestion("Select auth mode (oauth/api_key): ");
  return answer.trim() === "api_key" ? "api_key" : "oauth";
}

async function interactiveSelectLoginMode(): Promise<"oauth" | "api_key"> {
  return new Promise((resolve, reject) => {
    const readline = require("node:readline");
    const { input, output, cleanup: baseCleanup } = getInteractiveStreams();
    readline.emitKeypressEvents(input);
    input.setRawMode(true);

    const options: Array<{ label: string; value: "oauth" | "api_key" }> = [
      { label: "OpenAI Codex OAuth (browser)", value: "oauth" },
      { label: "OpenAI API Key (manual)", value: "api_key" }
    ];
    let index = 0;

    const render = () => {
      output.write("\x1b[2J\x1b[H");
      output.write("Select authentication method\n");
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
  } catch (err) {
    throw new Error("No TTY available for interactive selection.");
  }
}

type ModelSource = "codex" | "openai";

async function chooseModel(params: {
  current?: string;
  source?: ModelSource;
  provider: Provider;
  apiKey?: string;
}): Promise<string | undefined> {
  const { current, source, apiKey, provider } = params;
  const models =
    provider === "openai" && source === "openai" && apiKey
      ? await fetchOpenAiModels(apiKey)
      : provider === "openai" && source === "codex"
        ? getCodexModelChoices()
        : getProviderModelChoices(provider);

  return promptForModel({
    current,
    models
  });
}

function getCodexModelChoices(): string[] {
  return [
    "openai-codex/gpt-5.1",
    "openai-codex/gpt-5.1-codex-max",
    "openai-codex/gpt-5.1-codex-mini",
    "openai-codex/gpt-5.2",
    "openai-codex/gpt-5.2-codex",
    "openai-codex/gpt-5.3-codex",
    "openai-codex/gpt-5.3-codex-spark"
  ];
}

async function fetchOpenAiModels(apiKey: string): Promise<string[]> {
  const res = await fetch("https://api.openai.com/v1/models", {
    headers: {
      Authorization: `Bearer ${apiKey}`
    }
  });
  if (!res.ok) {
    return [];
  }
  const data = (await res.json()) as { data?: Array<{ id: string }> };
  const ids = data.data?.map((m) => m.id) ?? [];
  return unique(ids).sort();
}

function unique(items: string[]): string[] {
  return Array.from(new Set(items));
}

async function promptForModel(params: {
  current?: string;
  models: string[];
}): Promise<string | undefined> {
  const { current, models } = params;
  const choices = [
    { name: `Keep current${current ? ` (${current})` : ""}`, value: undefined },
    ...models.map((id) => ({ name: id, value: id })),
    { name: "Custom model id…", value: "__custom__" as unknown as string }
  ];

  const selected = await selectFromList("Default model", choices);
  if (selected === "__custom__") {
    const custom = await askQuestion("Enter custom model id: ");
    return custom.trim() || undefined;
  }
  return selected;
}

async function selectFromList<T extends string | undefined>(
  message: string,
  choices: Array<{ name: string; value: T }>
): Promise<T> {
  return interactiveSelect(message, choices);
}

async function interactiveSelect<T extends string | undefined>(
  message: string,
  choices: Array<{ name: string; value: T }>
): Promise<T> {
  return new Promise((resolve, reject) => {
    const readline = require("node:readline");
    const { input, output, cleanup: baseCleanup } = getInteractiveStreams();
    readline.emitKeypressEvents(input);
    input.setRawMode(true);

    let index = 0;

    const render = () => {
      output.write("\x1b[2J\x1b[H");
      output.write(`${message}\n`);
      for (let i = 0; i < choices.length; i += 1) {
        const prefix = i === index ? "●" : "○";
        output.write(`${prefix} ${choices[i].name}\n`);
      }
      output.write("\nUse ↑/↓ to move, Enter to select.\n");
    };

    const onKeypress = (_: string, key: { name?: string; ctrl?: boolean }) => {
      if (key.ctrl && key.name === "c") {
        cleanup();
        reject(new Error("Selection cancelled."));
        return;
      }
      if (key.name === "down") {
        index = (index + 1) % choices.length;
        render();
        return;
      }
      if (key.name === "up") {
        index = (index - 1 + choices.length) % choices.length;
        render();
        return;
      }
      if (key.name === "return") {
        const value = choices[index].value;
        cleanup();
        resolve(value);
      }
    };

    const cleanup = () => {
      input.off("keypress", onKeypress as any);
      baseCleanup();
    };

    input.on("keypress", onKeypress as any);
    render();
  });
}

type OAuthTokenResponse = {
  access_token?: string;
  refresh_token?: string;
  id_token?: string;
  token_type?: string;
  expires_in?: number;
  scope?: string;
};

async function exchangeCodeForTokens(params: {
  code: string;
  codeVerifier: string;
  clientId: string;
  redirectUri: string;
}): Promise<OAuthTokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: params.clientId,
    code_verifier: params.codeVerifier,
    code: params.code,
    redirect_uri: params.redirectUri
  });

  const res = await fetch("https://auth.openai.com/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`OAuth token exchange failed: ${res.status} ${text}`);
  }

  return res.json();
}

async function chooseProvider(current: Provider): Promise<Provider> {
  const choices: Array<{ name: string; value: Provider }> = [
    { name: "OpenAI", value: "openai" },
    { name: "Anthropic", value: "anthropic" },
    { name: "Google Gemini", value: "google" },
    { name: "Mistral", value: "mistral" },
    { name: "xAI", value: "xai" },
    { name: "Cohere", value: "cohere" }
  ];
  const selected = await selectFromList(`Provider (current: ${current})`, choices);
  return selected ?? current;
}

function providerLabel(provider: Provider): string {
  switch (provider) {
    case "openai":
      return "OpenAI";
    case "anthropic":
      return "Anthropic";
    case "google":
      return "Google Gemini";
    case "mistral":
      return "Mistral";
    case "xai":
      return "xAI";
    case "cohere":
      return "Cohere";
    default:
      return "Provider";
  }
}

function getProviderModelChoices(provider: Provider): string[] {
  switch (provider) {
    case "anthropic":
      return [
        "claude-opus-4-6",
        "claude-sonnet-4-6",
        "claude-haiku-4-5-20251001"
      ];
    case "google":
      return [
        "gemini-2.5-pro",
        "gemini-2.5-flash",
        "gemini-2.5-flash-lite",
        "gemini-flash-latest"
      ];
    case "mistral":
      return [
        "mistral-large-latest",
        "mistral-medium-latest",
        "mistral-small-latest",
        "codestral-latest",
        "devstral-latest",
        "devstral-small-latest",
        "magistral-medium-latest",
        "magistral-small-latest",
        "ministral-14b-latest",
        "ministral-8b-latest",
        "ministral-3b-latest"
      ];
    case "xai":
      return [
        "grok-4-1-fast-reasoning",
        "grok-4-1-fast-non-reasoning",
        "grok-4-fast-reasoning",
        "grok-4-fast-non-reasoning"
      ];
    case "cohere":
      return [
        "command-a-03-2025",
        "command-a-reasoning-08-2025"
      ];
    case "openai":
    default:
      return [
        "gpt-5.2",
        "gpt-5.1",
        "gpt-4.1",
        "gpt-4o-mini"
      ];
  }
}
