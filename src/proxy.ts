import http from "node:http";
import { URL, pathToFileURL } from "node:url";

type ProxyOptions = {
  port?: number;
};

const DEFAULT_PORT = 8787;
const DEFAULT_OPENAI_BASE = "https://api.openai.com";


export async function startProxyServer(options: ProxyOptions = {}): Promise<void> {
  const port = options.port ?? Number(process.env.OPENSECURITY_PROXY_PORT ?? DEFAULT_PORT);
  const openaiBase = process.env.OPENSECURITY_OPENAI_BASE ?? DEFAULT_OPENAI_BASE;
  const proxyApiKey = process.env.OPENSECURITY_PROXY_API_KEY;
  if (!proxyApiKey || !proxyApiKey.trim()) {
    throw new Error("OPENSECURITY_PROXY_API_KEY is required to run the OAuth backend.");
  }

  const server = http.createServer(async (req, res) => {
    try {
      if (req.method !== "POST") {
        res.writeHead(405);
        res.end("Method Not Allowed");
        return;
      }

      const url = new URL(req.url ?? "/", `http://localhost:${port}`);
      if (url.pathname !== "/v1/responses" && url.pathname !== "/v1/chat/completions") {
        res.writeHead(404);
        res.end("Not Found");
        return;
      }

      const auth = req.headers.authorization ?? "";
      if (!auth.startsWith("Bearer ")) {
        res.writeHead(401);
        res.end("Missing Authorization Bearer token.");
        return;
      }

      const bearerToken = auth.slice("Bearer ".length).trim();
      const apiKey = resolveApiKey(bearerToken, proxyApiKey);
      if (!bearerToken.startsWith("sk-")) {
        await validateOauthToken(bearerToken);
      }

      const body = await readRequestBody(req);
      const upstreamUrl = `${openaiBase}${url.pathname}${url.search}`;

      const upstreamRes = await fetch(upstreamUrl, {
        method: "POST",
        headers: {
          "Content-Type": req.headers["content-type"] ?? "application/json",
          Authorization: `Bearer ${apiKey}`
        },
        body
      });

      const responseBody = await upstreamRes.arrayBuffer();
      res.writeHead(upstreamRes.status, {
        "Content-Type": upstreamRes.headers.get("content-type") ?? "application/json"
      });
      res.end(Buffer.from(responseBody));
    } catch (err: any) {
      res.writeHead(500);
      res.end(err?.message ?? "Proxy error.");
    }
  });

  await new Promise<void>((resolve) => server.listen(port, resolve));
  console.log(`OpenSecurity OAuth proxy listening on http://localhost:${port}`);
  console.log("Forwarding OpenAI API requests for Codex OAuth tokens.");
}

function resolveApiKey(token: string, proxyApiKey?: string): string {
  if (proxyApiKey && proxyApiKey.trim()) {
    return proxyApiKey.trim();
  }

  if (!token.startsWith("sk-")) {
    throw new Error("Proxy requires OPENSECURITY_PROXY_API_KEY to call OpenAI with OAuth tokens.");
  }

  return token;
}

async function validateOauthToken(token: string): Promise<void> {
  const res = await fetch("https://auth.openai.com/userinfo", {
    headers: { Authorization: `Bearer ${token}` }
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`OAuth token validation failed: ${res.status} ${text}`);
  }
}

function readRequestBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

const isEntryPoint = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isEntryPoint) {
  startProxyServer().catch((err) => {
    console.error(err?.message ?? err);
    process.exit(1);
  });
}
