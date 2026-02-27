# opensecurity

CLI skeleton for openSecurity.

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

## Config

- Global: `~/.config/opensecurity/config.json`
- Project: `.opensecurity.json`
  - `rulesPath`: path to a JSON rule pack (relative to project root)
  - `cveCachePath`: path to CVE cache JSON (relative to project root)
  - `cveApiUrl`: CVE API URL
  - `dataSensitivity`: low|medium|high

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

## Dev

- `npm run dev`
- `npm run test`
