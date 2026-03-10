# OpenSecurity

OpenSecurity is an open-source CLI for scanning JavaScript/TypeScript codebases for security risks.
It combines:

- Static analysis with AST-based taint rules (OWASP-focused).
- Dependency scanning with CVE lookup (local cache or API).
- Optional AI-assisted scanning for deeper findings.

## Quick Start

```bash
npm install
npm run dev -- scan --dry-run
```

Build the CLI:

```bash
npm run build
./dist/cli.js scan --dry-run
```

## Features

- AST taint engine with configurable sources/sinks/sanitizers.
- OWASP-aligned default rules (injection, SSRF, path traversal, XSS templates, SQLi).
- Pattern-based detectors (hardcoded secrets, insecure crypto, unsafe deserialization).
- Dependency scanning for npm and PyPI (`package.json`, `package-lock.json`, `requirements.txt`).
- Text, JSON, and SARIF output.
- Optional AI scan (API key or OAuth flow).
- Configurable include/exclude filters and scan scope.

## CLI

### `scan`

```bash
opensecurity scan [options]
```

Common options:

- `--format <format>`: `text|json|sarif` (default: `text`)
- `--include <pattern...>` / `--exclude <pattern...>`: override project filters
- `--rules <path>`: rules JSON override
- `--cve-cache <path>`: CVE cache JSON
- `--cve-api-url <url>`: CVE lookup API endpoint
- `--simulate`: include payload + impact for dependency findings
- `--dependency-only`: only run dependency scan
- `--no-ai`: disable AI scanning
- `--dry-run`: list matched files without scanning
- `--fail-on <severity>`: exit 1 if findings >= severity
- `--sarif-output <path>`: write SARIF alongside primary output
- `--concurrency <n>`: parallel scan workers
- `--max-chars <n>`: max chars per chunk for AI scanning

### `login`

```bash
opensecurity login --mode oauth
opensecurity login --mode api_key
```

Stores auth config in `~/.config/opensecurity/config.json`.

### `proxy`

```bash
opensecurity proxy --port 8787
```

Runs a local OAuth proxy for the OAuth flow.

### `telemetry`

```bash
opensecurity telemetry on
opensecurity telemetry off
```

## Configuration

### Precedence

1. CLI flags
2. Project config (`.opensecurity.json`)
3. Global config (`~/.config/opensecurity/config.json`)
4. Built-in defaults

Project config: `.opensecurity.json`

```json
{
  "include": ["**/*.ts", "**/*.tsx"],
  "exclude": ["**/*.test.ts"],
  "rulesPath": "rules.json",
  "cveCachePath": "cve-cache.json",
  "cveApiUrl": "https://example.com/osv",
  "dataSensitivity": "medium",
  "maxChars": 4000,
  "concurrency": 2
}
```

Global config: `~/.config/opensecurity/config.json`

```json
{
  "apiKey": "sk-...",
  "baseUrl": "https://api.openai.com/v1/responses",
  "model": "gpt-4o-mini",
  "apiType": "responses",
  "authMode": "api_key",
  "authProfileId": "codex",
  "oauthProvider": "proxy"
}
```

## Rules

Default rules are in `src/rules/defaultRules.ts`.
You can override with a JSON file (`--rules` or `rulesPath`).

Pattern-based detectors run alongside rules (hardcoded secrets, insecure crypto, unsafe deserialization).

Rule schema (simplified):

```json
{
  "id": "rule-id",
  "name": "Human name",
  "severity": "low|medium|high|critical",
  "owasp": "A03:2021 Injection",
  "sources": [{ "id": "src", "name": "getUserInput", "matcher": { "callee": "getUserInput" } }],
  "sinks": [{ "id": "sink", "name": "eval", "matcher": { "callee": "eval" } }],
  "sanitizers": [{ "id": "san", "name": "escape", "matcher": { "callee": "escape" } }]
}
```

## Output

- **Text**: grouped by severity
- **JSON**: machine-readable, includes `schemaVersion`
- **SARIF**: for CI and code scanning tools

## Language Support

- Static analysis: JavaScript and TypeScript
- Dependency scanning: npm and PyPI manifests

## Security Notes

- Do not commit secrets.
- AI scanning sends code chunks to the configured API endpoint.
- Use `--no-ai` if you want purely local scanning.

## Development

```bash
npm install
npm run dev -- scan --dry-run
npm test
```

## License

MIT (see `LICENSE`).
