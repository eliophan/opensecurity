# OpenSecurity — VS Code Extension

Security scanner for VS Code with quick scan and inline highlights.

## Features

- **Quick Scan**: Run `OpenSecurity: Run Security Scan` from the command palette (`Cmd+Shift+P`)
- **Inline Diagnostics**: Findings appear in the Problems panel with inline highlights
- **Scan on Save**: Optionally auto-scan files on save
- **Clear Diagnostics**: Run `OpenSecurity: Clear Diagnostics` to reset

## Requirements

- OpenSecurity CLI installed in the workspace (`npm install opensecurity`)
- Node.js 20+

## Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `opensecurity.noAi` | boolean | `false` | Skip AI scanning |
| `opensecurity.rulesPath` | string | `""` | Path to custom OWASP rules JSON |
| `opensecurity.cveCachePath` | string | `""` | Path to CVE cache JSON |
| `opensecurity.dataSensitivity` | enum | `"medium"` | Risk scoring sensitivity |
| `opensecurity.scanOnSave` | boolean | `false` | Auto-scan on save |

## Development

```bash
cd vscode-extension
npm install
npm run compile
# Press F5 in VS Code to launch extension host
```

## Packaging

```bash
npm run package
# Produces opensecurity-vscode-0.1.0.vsix
```
