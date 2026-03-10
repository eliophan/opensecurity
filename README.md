# OpenSecurity

OpenSecurity is an open-source CLI that scans repositories for security risks using multiple engines:

- **Static analysis (AST + taint rules)** for JavaScript/TypeScript.
- **Universal static patterns** for popular languages (Python, Go, Java, C#, Ruby, PHP, Rust, Kotlin, Swift, C/C++).
- **External language adapters** (when installed): Bandit (Python), gosec (Go), Brakeman (Ruby), Semgrep (Java/C#/PHP/Rust/Kotlin/Swift/C/C++).
- **Infra/config patterns** for Dockerfile, Kubernetes/Helm YAML, Terraform, and generic YAML misconfigurations.
- **Pattern detectors** for common mistakes (secrets, crypto misuse, unsafe deserialization).
- **Dependency CVE scanning** for npm/PyPI.
- **AI scanning** across all text files by default (can be disabled with `--no-ai`).

## Project Status

Active. This repo is maintained and intended for open-source use. Contributions are welcome.

## Scope

- Native static analysis: JavaScript and TypeScript (AST + taint + patterns).
- Adapter-based static analysis (if tools installed): Python, Go, Java, C#, PHP, Ruby, Rust, Kotlin, Swift, C/C++.
- Infra/config static patterns: Dockerfile, Kubernetes/Helm YAML, Terraform, generic YAML.
- Dependency scanning: npm and PyPI manifests.
- AI scanning is optional and requires an API key (defaults to scanning all text files).

## Non-Goals

- This tool is not a full SAST replacement or compliance scanner.
- It does not execute or sandbox code.
- It does not guarantee complete coverage of all vulnerabilities.

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

## Install

From source:

```bash
npm install
npm run build
npm link
opensecurity scan --dry-run
```

## Supported Platforms

- Node.js 20+
- macOS, Linux, Windows

## Features

- AST taint engine with configurable sources/sinks/sanitizers.
- OWASP-aligned default rules (injection, SSRF, path traversal, XSS templates, SQLi).
- Pattern-based detectors (hardcoded secrets, insecure crypto, unsafe deserialization).
- Optional external adapters for top languages (Bandit, gosec, Brakeman, Semgrep).
- Dependency scanning for npm and PyPI (`package.json`, `package-lock.json`, `requirements.txt`).
- Text, JSON, and SARIF output.
- Optional AI scan (API key or OAuth flow) with multiple providers.
- Configurable include/exclude filters and scan scope.

## How It Works

1. **File discovery**
   - Walks the repository based on `include`/`exclude`.
   - Optional `--diff-only` or `--path` to narrow scope.

2. **Static analysis (JS/TS)**
   - Parses JS/TS with Babel and runs taint rules (sources → sinks → sanitizers).
   - Emits OWASP-aligned findings.

3. **Pattern detectors (JS/TS)**
   - Finds hardcoded secrets, insecure crypto, and unsafe deserialization.

4. **AI scan (all text files by default)**
   - Splits files into chunks and sends to the configured model.
   - Optional multi‑agent batching with shared leader context.
   - Optional per‑file cache to skip unchanged files.

5. **External language adapters**
   - Runs optional tool adapters when installed (Bandit, gosec, Brakeman, Semgrep).
   - Each adapter only runs if matching files exist and the tool is on PATH.

6. **Infra/config patterns**
   - Scans Dockerfile, Terraform, and Kubernetes/Helm YAML for risky defaults.

7. **Dependency scan**
   - Reads `package.json`, `package-lock.json`, and `requirements.txt`.
   - Matches against CVE cache or API and adds recommendations.

8. **Reporting**
   - Outputs text, JSON, or SARIF.
   - Optional `--fail-on`/`--fail-on-high` for CI gating.

## External Adapters

OpenSecurity can run optional external tools when they are installed and found on `PATH`.

- `bandit` → Python
- `gosec` → Go
- `brakeman` → Ruby
- `semgrep` → Java, C#, PHP, Rust, Kotlin, Swift, C/C++

Adapters only run when matching files exist. Use `--disable-adapters` to skip or `--adapters` to whitelist.

## Infra/Config Coverage

Built-in infra checks include:

- Dockerfile: `USER root`, privileged flags/capabilities.
- Kubernetes/Helm YAML: `privileged`, `allowPrivilegeEscalation`, `readOnlyRootFilesystem:false`, `runAsNonRoot:false`, `runAsUser:0`, `seccompProfile: Unconfined`, `hostNetwork/hostPID/hostIPC`, `hostPath`.
- Terraform: public security group ingress, public ACLs, public S3 ACLs, disabled S3 public access block, public RDS instances.
- YAML: insecure TLS (`insecureSkipVerify`, `verify_ssl: false`).

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
- `--provider <provider>`: `openai|anthropic|google|mistral|xai|cohere`
- `--ai-all-text`: allow AI scan on all text files (non-JS/TS) (default)
- `--ai-js-only`: limit AI scan to JS/TS only
- `--path <path>`: scan a specific file or directory
- `--diff-only`: scan only files changed in git
- `--diff-base <ref>`: git base ref for diff-only (default: HEAD)
- `--ai-multi-agent`: split AI scan into worker batches
- `--ai-batch-size <n>`: files per AI worker batch (default: 25)
- `--ai-batch-depth <n>`: path depth for AI batching (default: 2)
- `--ai-cache`: enable AI per-file cache (default)
- `--no-ai-cache`: disable AI per-file cache
- `--ai-cache-path <path>`: path to AI cache file
- `--adapters <list>`: comma-separated adapter ids (bandit,gosec,brakeman,semgrep)
- `--disable-adapters`: disable external static adapters
- `--dependency-only`: only run dependency scan
- `--no-ai`: disable AI scanning
- `--dry-run`: list matched files without scanning
- `--fail-on <severity>`: exit 1 if findings >= severity
- `--fail-on-high`: exit 1 if findings >= high
- `--sarif-output <path>`: write SARIF alongside primary output
- `--concurrency <n>`: parallel scan workers
- `--max-chars <n>`: max chars per chunk for AI scanning

Example commands:

```bash
opensecurity scan --no-ai
opensecurity scan --format sarif --sarif-output reports/opensecurity.sarif
opensecurity scan --provider anthropic --model claude-sonnet-4-20250514
opensecurity scan --dependency-only --simulate
opensecurity scan --ai-multi-agent --ai-batch-size 25 --ai-batch-depth 2
opensecurity scan --diff-only --diff-base main
opensecurity scan --path src/
opensecurity scan --adapters bandit,gosec
opensecurity scan --disable-adapters
```

### `login`

```bash
opensecurity login --mode oauth
opensecurity login --mode api_key
opensecurity login --mode api_key --provider anthropic
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
  "concurrency": 2,
  "aiCache": true,
  "aiCachePath": ".opensecurity/ai-cache.json",
  "adapters": ["bandit", "gosec", "brakeman", "semgrep"],
  "noAdapters": false
}
```

Global config: `~/.config/opensecurity/config.json`

```json
{
  "provider": "openai",
  "apiKey": "sk-...",
  "baseUrl": "https://api.openai.com/v1/responses",
  "model": "gpt-4o-mini",
  "apiType": "responses",
  "authMode": "api_key",
  "authProfileId": "codex",
  "oauthProvider": "proxy",
  "providerApiKey": "..."
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
- This tool provides best-effort findings and should be validated in your environment.

## Providers

Supported providers for AI scanning:

- OpenAI (Responses or Chat Completions)
- Anthropic Messages API
- Google Gemini API
- Mistral Chat Completions API
- xAI Chat Completions API
- Cohere Chat API

API keys can be stored via `opensecurity login --mode api_key --provider <provider>` or set via environment:

- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `GEMINI_API_KEY`
- `MISTRAL_API_KEY`
- `XAI_API_KEY`
- `COHERE_API_KEY`

When an API key is available, the model picker will try to fetch a live model list for the provider.

## Contributing

- Run `npm test`, `npm run lint`, and `npm run build` before submitting changes.
- Keep changes focused and add tests for new behavior.
- Do not add or log real secrets.
- For large changes, open an issue first to align on scope.

See `CONTRIBUTING.md` for full guidelines.

## Security

If you discover a vulnerability:

- Prefer opening a private **Security Advisory** on GitHub (if enabled), or
- Open a minimal public issue without sensitive details and request private follow‑up.

## Support

For questions or help, open a GitHub issue with clear reproduction steps.

## Development

```bash
npm install
npm run dev -- scan --dry-run
npm test
```

## License

MIT (see `LICENSE`).
