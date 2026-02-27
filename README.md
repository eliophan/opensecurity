# opensecurity

CLI skeleton for openSecurity.

## Commands

- `opensecurity login`
- `opensecurity scan`
  - `--dry-run` to list matched files only
  - `--include <pattern...>` to override include globs
  - `--exclude <pattern...>` to override exclude globs
  - `--cwd <path>` to override working directory

## Config

- Global: `~/.config/opensecurity/config.json`
- Project: `.opensecurity.json`

## Dev

- `npm run dev`
- `npm run test`
