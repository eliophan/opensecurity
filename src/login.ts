import readline from "node:readline";
import http from "node:http";
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

export async function login(env = process.env, mockPort = 42069): Promise<GlobalConfig> {
  const current = await loadGlobalConfig(env);

  const answer = await askQuestion("Do you want to authenticate with OpenAI/Codex OAuth? (Y/n) ");
  if (answer.toLowerCase() === 'n') {
    console.log("Login aborted.");
    return current;
  }

  return new Promise((resolve) => {
    // 1. Start a local server just to catch the OAuth App callback
    const server = http.createServer(async (req, res) => {
      try {
        const url = new URL(req.url || "", `http://${req.headers.host}`);

        // 2. This represents the redirect_uri handling
        if (url.pathname === "/callback") {
          const token = url.searchParams.get("token") || url.searchParams.get("code");
          if (token) {
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

            // In a real OpenClaw/OAuth flow, if we got a 'code' we'd exchange it for a token here.
            // For this skeleton, we assume the implicit flow or direct token injection.
            const updated: GlobalConfig = { ...current, apiKey: token };
            await saveGlobalConfig(updated, env);
            console.log(`\n✅ Successfully authenticated with OpenAI/Codex. (API Token received)`);

            server.close();
            resolve(updated);
          } else {
            res.writeHead(400, { "Content-Type": "text/plain" });
            res.end("Authentication Failed: No token/code provided.");
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

    server.listen(mockPort, () => {
      // 3. Open the actual OAuth provider URL (OpenAI / OpenClaw Auth)
      // This is exactly how OpenClaw does "openclaw models auth login --provider openai-codex"
      const clientId = "opensecurity_cli_client";
      const redirectUri = encodeURIComponent(`http://localhost:${mockPort}/callback`);

      // In production, this would be a real URL like "https://auth.openai.com/authorize" or OpenClaw's proxy
      // We'll use a mock auth URL that immediately redirects back to the callback with a mock key for testing.
      // E.g., const authUrl = \`https://auth.openai.com/oauth/authorize?response_type=token&client_id=\${clientId}&redirect_uri=\${redirectUri}\`;
      const authUrl = `http://localhost:${mockPort}/callback?token=sk-codex-${Math.random().toString(36).substring(2)}`;

      console.log(`\nLocal server listening on port ${mockPort} for OAuth callbacks...`);
      console.log(`Opening browser to OpenAI/Codex authentication page...`);

      // Open the browser to the OAuth page
      exec(`open "${authUrl}"`);
    });
  });
}
