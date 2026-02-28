import http from "node:http";
import { URL, pathToFileURL } from "node:url";

type ProxyOptions = {
  port?: number;
};

const DEFAULT_PORT = 8787;
const DEFAULT_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const DEFAULT_OAUTH_ISSUER = "https://auth.openai.com";
const DEFAULT_OPENAI_BASE = "https://api.openai.com";
const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000;

type CachedKey = {
  apiKey: string;
  expiresAt: number;
};

const apiKeyCache = new Map<string, CachedKey>();

export async function startProxyServer(options: ProxyOptions = {}): Promise<void> {
  const port = options.port ?? Number(process.env.OPENSECURITY_PROXY_PORT ?? DEFAULT_PORT);
  const clientId = process.env.OPENSECURITY_OAUTH_CLIENT_ID ?? DEFAULT_CLIENT_ID;
  const oauthIssuer = process.env.OPENSECURITY_OAUTH_ISSUER ?? DEFAULT_OAUTH_ISSUER;
  const openaiBase = process.env.OPENSECURITY_OPENAI_BASE ?? DEFAULT_OPENAI_BASE;
  const cacheTtlMs = Number(process.env.OPENSECURITY_PROXY_CACHE_TTL_MS ?? DEFAULT_CACHE_TTL_MS);

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
      const apiKey = await resolveApiKey(bearerToken, {
        clientId,
        oauthIssuer,
        cacheTtlMs
      });

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

async function resolveApiKey(
  token: string,
  params: { clientId: string; oauthIssuer: string; cacheTtlMs: number }
): Promise<string> {
  if (token.startsWith("sk-")) {
    return token;
  }

  const cached = apiKeyCache.get(token);
  if (cached && Date.now() < cached.expiresAt) {
    return cached.apiKey;
  }

  const apiKey = await exchangeIdTokenForApiKey(token, params);
  apiKeyCache.set(token, { apiKey, expiresAt: Date.now() + params.cacheTtlMs });
  return apiKey;
}

async function exchangeIdTokenForApiKey(
  idToken: string,
  params: { clientId: string; oauthIssuer: string }
): Promise<string> {
  const body = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    client_id: params.clientId,
    subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
    subject_token: idToken,
    requested_token_type: "urn:openai:params:oauth:token-type:api_key"
  });

  const res = await fetch(`${params.oauthIssuer}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`OAuth token exchange failed: ${res.status} ${text}`);
  }

  const data = (await res.json()) as { access_token?: string };
  if (!data.access_token) {
    throw new Error("OAuth token exchange did not return an access token.");
  }
  return data.access_token;
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
