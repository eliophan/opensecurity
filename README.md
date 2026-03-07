# OpenSecurity (Outdated)

> **OUTDATED / ARCHIVED**
> This repository is no longer maintained and its implementation and documentation are outdated.
> Do not rely on this project for production security scanning.

## Current Guidance (Use These Instead)

If you're looking for current, supported security scanning solutions, refer to:

- [OpenAI Codex Security](https://developers.openai.com/codex/security)
- [Claude Code Security](https://claude.com/solutions/claude-code-security)

These products describe modern, actively maintained approaches for code security scanning, validation, and remediation workflows.

## What This Repo Contains (Historical)

This project was an experimental, open-source CLI that combined:

- Deterministic static analysis (AST rules for JS/TS)
- Optional AI-assisted review
- Dependency CVE lookup via a local cache
- Text/JSON reporting

The original CLI entry point is in `src/cli.ts`, with compiled output in `dist/`.

## Confidentiality & Secrets (Read This)

- **No secrets should ever be committed.** This repo must not contain API keys, tokens, or credentials.
- Global config was stored outside the repo at `~/.config/opensecurity/config.json`.
  - If you used this project in the past, verify that file does **not** contain any active secrets.
  - Rotate and revoke any credentials that may have been exposed.
- Do not add real customer data, production logs, or private datasets to this repository.

## Safety Notes

Because this repo is outdated:

- The scanner may miss vulnerabilities or generate incorrect results.
- Dependencies and model integrations may be stale or insecure.
- There is no guarantee of ongoing maintenance or fixes.

## License

MIT (see `LICENSE`).
