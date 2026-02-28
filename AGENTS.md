# Repository Guidelines

## Project Structure & Module Organization

- `src/` contains the TypeScript source (CLI entry at `src/cli.ts`).
- `tests/` holds Vitest tests named `*.test.ts` (e.g., `tests/scan.test.ts`).
- `dist/` is the compiled output (`npm run build`) and exposes the CLI binaries.
- `examples/` provides intentionally vulnerable samples for local scans.
- Configuration defaults live in `.opensecurity.json`; sample CVE data is in `cve-cache.json`.

## Build, Test, and Development Commands

- `npm install` installs dependencies.
- `npm run dev -- <cmd>` runs the CLI in TS via `tsx` (example: `npm run dev -- scan --verbose`).
- `npm run build` compiles `src/` to `dist/` with `tsc`.
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

## Commit & Pull Request Guidelines

- Commit messages follow Conventional Commits, often with scopes (e.g., `feat(auth): ...`, `refactor(scan): ...`, `docs: ...`).
- PRs should include:
  - A concise summary of changes and rationale.
  - Tests run (e.g., `npm test`) or a note if not run.
  - CLI UX changes documented in `README.md` when applicable.

## Security & Configuration Notes

- `.opensecurity.json` and `~/.config/opensecurity/config.json` control runtime behavior.
- Treat API keys and tokens as secrets; avoid committing them or logging them in tests.
