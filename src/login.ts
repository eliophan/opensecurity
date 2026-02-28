import readline from "node:readline";
import http from "node:http";
import crypto from "node:crypto";
import { exec } from "node:child_process";
import { loadGlobalConfig, saveGlobalConfig, type GlobalConfig } from "./config.js";

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

export async function login(env = process.env): Promise<GlobalConfig> {
  console.log("\n\x1b[32m\u25C7\x1b[0m  \x1b[1mOpenSecurity Authentication\x1b[0m");
  console.log("   Please choose your authentication method:\n");
  console.log("   1. OpenAI Codex (OAuth) - Recommended, browser-based.");
  console.log("   2. OpenAI API Key (Manual) - Direct access to OpenAI Platform.\n");

  const choice = await askQuestion("Select option (1 or 2): ");

  if (choice === "2") {
    const key = await askQuestion("Enter your OpenAI API Key (sk-...): ");
    if (!key.startsWith("sk-")) {
      console.error("\x1b[31mError: Invalid OpenAI API key format.\x1b[0m");
      process.exit(1);
    }
    const current = await loadGlobalConfig(env);
    const updated: GlobalConfig = { ...current, apiKey: key, authMode: "api_key" };
    await saveGlobalConfig(updated, env);
    console.log("\n✅ Successfully saved OpenAI API Key.");
    return updated;
  }

  // Option 1: Codex OAuth (Default)
  return codexOAuthLogin(env);
}

async function codexOAuthLogin(env = process.env, port = 1455): Promise<GlobalConfig> {
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

            if (!tokens.id_token) {
              throw new Error("OAuth token exchange did not return an id_token.");
            }

            const updated: GlobalConfig = {
              ...current,
              apiKey: tokens.id_token,
              baseUrl: proxyBaseUrl,
              apiType: "responses",
              authMode: "oauth"
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

type OAuthTokenResponse = {
  access_token?: string;
  refresh_token?: string;
  id_token?: string;
  token_type?: string;
  expires_in?: number;
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
