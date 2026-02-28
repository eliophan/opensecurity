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

  const answer = await askQuestion("Do you want to authenticate with Codex via browser? (Y/n) ");
  if (answer.toLowerCase() === 'n') {
    console.log("Login aborted.");
    return current;
  }

  return new Promise((resolve) => {
    const server = http.createServer(async (req, res) => {
      try {
        const url = new URL(req.url || "", `http://${req.headers.host}`);

        // This simulates the external Codex OAuth login page
        if (url.pathname === "/login") {
          res.writeHead(200, { "Content-Type": "text/html" });
          res.end(`
            <html>
              <head>
                <title>Codex Auth</title>
                <style>
                  body { font-family: -apple-system, sans-serif; padding: 2rem; max-width: 400px; margin: 40px auto; text-align: center; }
                  p { color: #555; margin-bottom: 30px;}
                  button { padding: 12px 24px; font-size: 16px; font-weight: bold; cursor: pointer; background: #000; color: white; border: none; border-radius: 6px; }
                  button:hover { background: #333; }
                </style>
              </head>
              <body>
                <h2>Codex Authentication</h2>
                <p><strong>OpenSecurity CLI</strong> is requesting access to your Codex account to perform AI static analysis.</p>
                <form action="/callback" method="GET">
                  <input type="hidden" name="token" value="codex_tok_${Math.random().toString(36).substring(2, 10)}" />
                  <button type="submit">Authorize OpenSecurity</button>
                </form>
              </body>
            </html>
          `);
        }

        // This simulates our local server receiving the OAuth redirect
        else if (url.pathname === "/callback") {
          const token = url.searchParams.get("token");
          if (token) {
            res.writeHead(200, { "Content-Type": "text/html" });
            res.end(`
              <html>
                <head><title>Success</title><style>body { font-family: sans-serif; text-align: center; margin-top: 50px; }</style></head>
                <body>
                  <h1>✅ Authentication Successful!</h1>
                  <p>You can close this window and return to your terminal.</p>
                  <script>window.close();</script>
                </body>
              </html>
            `);

            const updated: GlobalConfig = { ...current, apiKey: token };
            await saveGlobalConfig(updated, env);
            console.log(`\n✅ Successfully authenticated with Codex. (Token: ${token})`);

            server.close();
            resolve(updated);
          } else {
            res.writeHead(400, { "Content-Type": "text/plain" });
            res.end("Authentication Failed: No token provided.");
          }
        }

        else {
          res.writeHead(404);
          res.end("Not Found");
        }
      } catch (err) {
        res.writeHead(500);
        res.end("Internal error");
      }
    });

    server.listen(mockPort, () => {
      // In a real application, this URL points to the external identity provider
      // e.g., https://auth.codex.com/oauth/authorize?redirect_uri=http://localhost:42069/callback
      const loginUrl = `http://localhost:${mockPort}/login`;
      console.log(`\nLocal server listening for callbacks...`);
      console.log(`Opening browser to authenticate...`);
      exec(`open "${loginUrl}"`);
    });
  });
}
