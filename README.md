# opensecurity

CLI security scanner for open-source projects.

## Getting Started

1. **Install dependencies**: `npm install`
2. **Build**: `npm run build`
3. **Login**: `npm run dev -- login`
   - Choose **Option 1** for OpenAI Codex (OAuth).
   - Choose **Option 2** for Manual API Key (`sk-...`).
4. **Scan**: `npm run dev -- scan --verbose`

## OAuth Token (Codex)

Use this flow when you want to sign in with your OpenAI/ChatGPT account instead of pasting an API key.

1. Run `opensecurity login` (or `npm run dev -- login` during development).
2. Choose **Option 1** for OpenAI Codex (OAuth).
3. Your browser opens and completes the sign-in. The CLI listens on `http://localhost:1455/auth/callback`.
4. The resulting token is saved to `~/.config/opensecurity/config.json` under `apiKey`.

To use OAuth tokens for scanning, run the local proxy before scanning:

```bash
opensecurity proxy
# or
npm run proxy
```

You can override the proxy URL with `OPENSECURITY_PROXY_URL` if needed.

If you are in a headless environment or cannot open a browser, use **Option 2** and paste an API key instead.

## Examples

Run a scan on our provided vulnerable sample:
```bash
npm run dev -- scan --cwd examples --verbose
```

Features simulated/found in `examples/bad-code.js`:
- SQL Injection via `sqlite3`
- XSS via `express`
- Insecure Cryptography using `md5`

## Commands

- `opensecurity login` — Authenticate via OAuth or Manual API Key.
- `opensecurity scan` — Run AI security scan.
  - `--format json|text` to choose output format.
  - `--dry-run` to list matched files only.
  - `--no-ai` to skip AI scanning and run static checks only.
  - `--verbose` — show detailed progress and token estimation.
  - `--cwd <path>` to override working directory.
- `opensecurity telemetry on|off` — enable/disable anonymous telemetry.

## Config

- Global: `~/.config/opensecurity/config.json`
- Project: `.opensecurity.json`
  - `rulesPath`: path to a JSON rule pack (relative to project root)
  - `cveCachePath`: path to CVE cache JSON (relative to project root)
  - `cveApiUrl`: CVE API URL
  - `dataSensitivity`: low|medium|high

## Integrations

### GitHub Actions

A built-in workflow scans every PR automatically. Copy `.github/workflows/security-scan.yml` to your repo.

Set `CODEX_API_KEY` as a repository secret for AI-powered scanning.

### PR Comment Reporter

The `pr-comment.ts` script converts JSON scan results into a rich Markdown summary posted as a PR comment.

```bash
node dist/pr-comment.js scan-results.json > comment.md
```

## Telemetry

Telemetry is **opt-in** and disabled by default. Enable it with:

```bash
opensecurity telemetry on
```

Or via environment variable: `OPENSECURITY_TELEMETRY=1`

## CVE Cache

Sample cache: `cve-cache.json`

Schema (array of objects):
- `id` (string)
- `package` (string)
- `ecosystem` ("npm" | "pypi")
- `affectedRange` (string, semver range)
- `fixedVersion` (string, optional)
- `severity` ("low" | "medium" | "high" | "critical")

## Dev

- `npm run dev`
- `npm run test`
- `npm run build`
