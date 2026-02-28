# opensecurity

CLI security scanner for open-source projects.

## Commands

- `opensecurity login`
- `opensecurity scan`
  - `--dry-run` to list matched files only
  - `--include <pattern...>` to override include globs
  - `--exclude <pattern...>` to override exclude globs
  - `--rules <path>` to load a custom OWASP rule pack
  - `--cve-cache <path>` to load CVE cache JSON
  - `--cve-api-url <url>` to query a CVE API (optional)
  - `--simulate` to include payload + impact simulation for dependency findings
  - `--data-sensitivity <level>` low|medium|high for risk scoring
  - `--dependency-only` to run only dependency/CVE scanning
  - `--no-ai` to skip AI model scanning
  - `--cwd <path>` to override working directory
- `opensecurity telemetry on|off` — enable/disable anonymous telemetry

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

Set `CODEX_API_KEY` as a repository secret for AI-powered scanning. Without it, the scan runs in static-analysis-only mode (`--no-ai`).

### PR Comment Reporter

The `pr-comment.ts` script converts JSON scan results into a rich Markdown summary posted as a PR comment. It includes severity tables, grouped findings, package info, and patch recommendations.

```bash
node dist/pr-comment.js scan-results.json > comment.md
```

## Telemetry

Telemetry is **opt-in** and disabled by default. Enable it with:

```bash
opensecurity telemetry on
```

Or via environment variable: `OPENSECURITY_TELEMETRY=1`

Only anonymous, non-identifying metadata is collected (OS, arch, Node version, finding counts). No source code or secrets are ever sent.

## CVE Cache

Sample cache: `cve-cache.json`

Schema (array of objects):
- `id` (string)
- `package` (string)
- `ecosystem` ("npm" | "pypi")
- `affectedRange` (string, semver range)
- `fixedVersion` (string, optional)
- `severity` ("low" | "medium" | "high" | "critical")
- `cvssScore` (number, optional)
- `description` (string, optional)
- `references` (string[], optional)
- `exploitability` ("low" | "medium" | "high", optional)
- `privilegeRequired` ("none" | "low" | "high", optional)

## Examples

Check the `examples/` directory for sample reports:
- [Sample JSON Output](examples/sample-output.json)
- [Sample Text Output](examples/sample-output.txt)
- [Sample PR Comment Markdown](examples/sample-pr-comment.md)

## Dev

- `npm run dev`
- `npm run test`
- `npm run build`

