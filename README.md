# OpenSecurity

Open-source, user-facing hybrid security scanner for GitHub and CI.

## Vision

OpenSecurity combines deterministic static analysis with AI reasoning to deliver structured, CI-friendly security findings. The philosophy is simple: deterministic first, AI second, structured output always.

## Architecture

```
CLI
 ├── File Collector
 ├── AST Pre-Scanner (Deterministic Rules)
 ├── AI Analyzer (Codex CLI or OpenAI API)
 ├── Finding Normalizer
 ├── Reporter (Text / JSON)
 └── (Planned) Dedup / Severity / SARIF
```

## Execution Flow

1. **File collection**
   - Recursively walks the target directory.
   - Applies include/exclude filters from project config.
2. **Deterministic pre-scan (JS/TS)**
   - Parses AST with `@babel/parser` and runs taint rules.
   - Current rules cover: eval injection, command injection, SSRF.
3. **AI analysis (optional)**
   - Sends code chunks to AI for deeper reasoning.
   - OAuth mode uses Codex CLI (no model override is passed).
   - API key mode uses OpenAI Responses API.
4. **Reporting**
   - Outputs text or JSON.
   - Dependency CVE findings are included when enabled.

## Quickstart

```bash
npm install
npm run dev -- login --mode oauth
npm run dev -- scan --auth oauth --verbose
```

Scan the sample project:
```bash
npm run dev -- scan --auth oauth --cwd examples --verbose
```

## Authentication Modes

### OAuth (Codex CLI)

Best for local development. Uses Codex CLI transport and your ChatGPT OAuth session.

```bash
codex login
npm run dev -- login --mode oauth
npm run dev -- scan --auth oauth
```

Notes:
- No `--model` override is passed to Codex in OAuth mode.
- If you want a different Codex model, choose it during login.

### API Key (OpenAI API)

Best for CI and production scans.

```bash
npm run dev -- login --mode api_key
npm run dev -- scan --auth api_key
```

The API key is stored in `~/.config/opensecurity/config.json`.

## Commands

- `opensecurity login` — authenticate via OAuth or API key.
  - `--mode oauth|api_key`
  - `--model <model>` (default model saved to config)
- `opensecurity scan` — run a scan.
  - `--format text|json`
  - `--auth oauth|api_key`
  - `--dry-run`
  - `--no-ai`
  - `--dependency-only`
  - `--simulate`
  - `--rules <path>`
  - `--cve-cache <path>`
  - `--cve-api-url <url>`
  - `--include <glob...>` / `--exclude <glob...>`
  - `--verbose`
- `opensecurity telemetry on|off`
- `opensecurity proxy` — local OAuth proxy (optional, API mode only).

## Config

Global config: `~/.config/opensecurity/config.json`

Project config: `.opensecurity.json`

```json
{
  "rulesPath": "path/to/rules.json",
  "cveCachePath": "cve-cache.json",
  "cveApiUrl": "https://...",
  "dataSensitivity": "low|medium|high",
  "include": ["**/*"],
  "exclude": ["**/node_modules/**"]
}
```

## Output Formats

- `text`: human-readable CLI summary
- `json`: structured machine output

SARIF support is planned.

## Rule Packs

Rules are defined as JSON arrays (see `src/rules/defaultRules.ts`).
You can provide a custom rule pack with `--rules <path>`.

Profiles (OWASP/backend/frontend) are planned.

## CI / GitHub Actions

For CI, use API key mode and create config at runtime:

```bash
mkdir -p ~/.config/opensecurity
cat > ~/.config/opensecurity/config.json <<'JSON'
{
  "apiKey": "${OPENAI_API_KEY}",
  "authMode": "api_key",
  "baseUrl": "https://api.openai.com/v1/responses",
  "apiType": "responses",
  "model": "gpt-4o-mini"
}
JSON

node dist/cli.js scan --format json --cwd $GITHUB_WORKSPACE
```

## Roadmap (Planned)

- SARIF output
- Severity engine + confidence scoring
- Deduplication
- Rule profiles
- Language parsers beyond JS/TS

## Security Philosophy

Deterministic core. AI-enhanced reasoning. Structured output. CI-ready enforcement.
