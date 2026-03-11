# Repository Guidelines

## Project Structure & Module Organization

- `src/` contains the TypeScript source (CLI entry at `src/ui/cli.ts`).
- `tests/` holds Vitest tests named `*.test.ts` (e.g., `tests/scan.test.ts`).
- `dist/` is the compiled output (`npm run build`) and exposes the CLI binaries.
- `examples/` provides intentionally vulnerable samples for local scans.
- Configuration defaults live in `.opensecurity.json`; sample CVE data is in `cve-cache.json`.
- PR submission template (canonical): `.github/pull_request_template.md`.
- Issue submission templates (canonical): `.github/ISSUE_TEMPLATE/`.

## Build, Test, and Development Commands

- `npm install` installs dependencies.
- `npm run dev -- <cmd>` runs the CLI in TS via `tsx` (example: `npm run dev -- scan --verbose`).
- `npm run build` compiles `src/` to `dist/` with `tsc`.
- Release and publish to npm: `npm run build && npm publish`.
- `npm test` runs the Vitest suite once.
- `npm run lint` runs ESLint across the repo.

## Coding Style & Naming Conventions

- TypeScript is strict (`tsconfig.json`); keep types explicit when inference is unclear.
- Use ESM imports/exports and follow existing file style for spacing and ordering.
- Test files use the `*.test.ts` suffix; keep test names descriptive and behavior-driven.

## Testing Guidelines

- Framework: Vitest.
- Add or update tests in `tests/` for any CLI behavior, scanning logic, or config parsing.
- Prefer focused, fast unit tests; cover new flags and config fields with explicit cases.

## Security & Configuration Notes

- `.opensecurity.json` and `~/.config/opensecurity/config.json` control runtime behavior.
- Treat API keys and tokens as secrets; avoid committing them or logging them in tests.
- NEVER edit `.env` or any environment variable files—only the user may change them.

## Collaboration, Deletions, and Safety

- Delete unused or obsolete files when your changes make them irrelevant (refactors, feature removals, etc.), and revert files only when the change is yours or explicitly requested.
- If a git operation leaves you unsure about other agents' in-flight work, stop and coordinate instead of deleting.
- Coordinate with other agents before removing their in-progress edits—don't revert or delete work you didn't author unless everyone agrees.
- **Before attempting to delete a file to resolve a local type/lint failure, stop and ask the user.** Other agents are often editing adjacent files; deleting their work to silence an error is never acceptable without explicit approval.
- Moving/renaming and restoring files is allowed.

## Git & Commit Rules

- ABSOLUTELY NEVER run destructive git operations (e.g., `git reset --hard`, `rm`, `git checkout`/`git restore` to an older commit) unless the user gives an explicit, written instruction in this conversation. Treat these commands as catastrophic; if you are even slightly unsure, stop and ask before touching them. *(When working within Cursor or Codex Web, these git limitations do not apply; use the tooling's capabilities as needed.)*
- Never use `git restore` (or similar commands) to revert files you didn't author—coordinate with other agents instead so their in-progress work stays intact.
- When running `git rebase`, avoid opening editors—export `GIT_EDITOR=:` and `GIT_SEQUENCE_EDITOR=:` (or pass `--no-edit`) so the default messages are used automatically.
- Never amend commits unless you have explicit written approval in the task thread.
- Always double-check git status before any commit.
- Keep commits atomic: commit only the files you touched and list each path explicitly.
- For tracked files run `git commit -m "<scoped message>" -- path/to/file1 path/to/file2`.
- For brand-new files, use the one-liner `git restore --staged :/ && git add "path/to/file1" "path/to/file2" && git commit -m "<scoped message>" -- path/to/file1 path/to/file2`.
- Quote any git paths containing brackets or parentheses (e.g., `src/app/[candidate]/**`) when staging or committing so the shell does not treat them as globs or subshells.

## Commit & Pull Request Guidelines

- Commit messages follow Conventional Commits, often with scopes (e.g., `feat(auth): ...`, `refactor(scan): ...`, `docs: ...`).
- PRs should include:
  - A concise summary of changes and rationale.
  - Tests run (e.g., `npm test`) or a note if not run.
  - CLI UX changes documented in `README.md` when applicable.
