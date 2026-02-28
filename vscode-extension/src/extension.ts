import * as vscode from "vscode";
import { execFile } from "node:child_process";
import * as path from "node:path";

const DIAGNOSTIC_SOURCE = "OpenSecurity";
let diagnosticCollection: vscode.DiagnosticCollection;

interface Finding {
    id: string;
    severity: "low" | "medium" | "high" | "critical";
    title: string;
    description: string;
    file: string;
    line?: number;
    owasp?: string;
    category?: "code" | "dependency";
    packageName?: string;
    packageVersion?: string;
    cveId?: string;
    riskScore?: number;
    recommendation?: string;
}

interface ScanResult {
    findings: Finding[];
}

const SEVERITY_MAP: Record<string, vscode.DiagnosticSeverity> = {
    critical: vscode.DiagnosticSeverity.Error,
    high: vscode.DiagnosticSeverity.Error,
    medium: vscode.DiagnosticSeverity.Warning,
    low: vscode.DiagnosticSeverity.Information
};

export function activate(context: vscode.ExtensionContext): void {
    diagnosticCollection = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_SOURCE);
    context.subscriptions.push(diagnosticCollection);

    const scanCommand = vscode.commands.registerCommand("opensecurity.scan", async () => {
        await runScan();
    });

    const clearCommand = vscode.commands.registerCommand("opensecurity.clearDiagnostics", () => {
        diagnosticCollection.clear();
        vscode.window.showInformationMessage("OpenSecurity: Diagnostics cleared.");
    });

    context.subscriptions.push(scanCommand, clearCommand);

    // Optional scan-on-save
    const onSave = vscode.workspace.onDidSaveTextDocument(async () => {
        const config = vscode.workspace.getConfiguration("opensecurity");
        if (config.get<boolean>("scanOnSave", false)) {
            await runScan(true);
        }
    });
    context.subscriptions.push(onSave);
}

export function deactivate(): void {
    diagnosticCollection?.dispose();
}

async function runScan(silent = false): Promise<void> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders?.length) {
        vscode.window.showWarningMessage("OpenSecurity: No workspace folder open.");
        return;
    }

    const cwd = workspaceFolders[0].uri.fsPath;
    const config = vscode.workspace.getConfiguration("opensecurity");

    const args = ["scan", "--format", "json", "--cwd", cwd];

    if (config.get<boolean>("noAi", false)) {
        args.push("--no-ai");
    }

    const rulesPath = config.get<string>("rulesPath", "");
    if (rulesPath) {
        args.push("--rules", rulesPath);
    }

    const cveCachePath = config.get<string>("cveCachePath", "");
    if (cveCachePath) {
        args.push("--cve-cache", cveCachePath);
    }

    const dataSensitivity = config.get<string>("dataSensitivity", "medium");
    args.push("--data-sensitivity", dataSensitivity);

    const cliPath = findCliPath(cwd);

    if (!silent) {
        vscode.window.showInformationMessage("OpenSecurity: Scanning…");
    }

    try {
        const result = await runCli(cliPath, args, cwd);
        applyDiagnostics(result, cwd);

        const total = result.findings.length;
        if (!silent) {
            if (total === 0) {
                vscode.window.showInformationMessage("OpenSecurity: No findings detected. ✅");
            } else {
                const critical = result.findings.filter(
                    (f) => f.severity === "critical" || f.severity === "high"
                ).length;
                vscode.window.showWarningMessage(
                    `OpenSecurity: ${total} finding${total > 1 ? "s" : ""} (${critical} critical/high). Check Problems panel.`
                );
            }
        }
    } catch (err: any) {
        if (!silent) {
            vscode.window.showErrorMessage(`OpenSecurity: Scan failed — ${err.message ?? err}`);
        }
    }
}

function findCliPath(cwd: string): string {
    // Prefer local install, fall back to global
    const localCli = path.join(cwd, "node_modules", ".bin", "opensecurity");
    return localCli;
}

function runCli(cliPath: string, args: string[], cwd: string): Promise<ScanResult> {
    return new Promise((resolve, reject) => {
        execFile(cliPath, args, { cwd, maxBuffer: 10 * 1024 * 1024, timeout: 120000 }, (err, stdout, stderr) => {
            if (err) {
                // Try to parse partial output even on non-zero exit
                try {
                    const result = JSON.parse(stdout) as ScanResult;
                    resolve(result);
                    return;
                } catch {
                    reject(new Error(stderr || err.message));
                    return;
                }
            }

            const trimmed = stdout.trim();
            if (!trimmed || trimmed === "No findings.") {
                resolve({ findings: [] });
                return;
            }

            try {
                resolve(JSON.parse(trimmed) as ScanResult);
            } catch {
                reject(new Error(`Failed to parse scan output: ${trimmed.slice(0, 200)}`));
            }
        });
    });
}

function applyDiagnostics(result: ScanResult, cwd: string): void {
    diagnosticCollection.clear();

    const diagnosticMap = new Map<string, vscode.Diagnostic[]>();

    for (const finding of result.findings) {
        const filePath = path.isAbsolute(finding.file)
            ? finding.file
            : path.join(cwd, finding.file);

        const line = Math.max(0, (finding.line ?? 1) - 1);
        const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);

        const severity = SEVERITY_MAP[finding.severity] ?? vscode.DiagnosticSeverity.Warning;

        const message = buildDiagnosticMessage(finding);

        const diagnostic = new vscode.Diagnostic(range, message, severity);
        diagnostic.source = DIAGNOSTIC_SOURCE;
        diagnostic.code = finding.id;

        const existing = diagnosticMap.get(filePath) ?? [];
        existing.push(diagnostic);
        diagnosticMap.set(filePath, existing);
    }

    for (const [filePath, diagnostics] of diagnosticMap) {
        diagnosticCollection.set(vscode.Uri.file(filePath), diagnostics);
    }
}

function buildDiagnosticMessage(finding: Finding): string {
    const parts: string[] = [finding.title];

    if (finding.owasp) {
        parts.push(`[${finding.owasp}]`);
    }

    parts.push(`— ${finding.description}`);

    if (finding.category === "dependency" && finding.packageName) {
        const pkg = finding.packageVersion
            ? `${finding.packageName}@${finding.packageVersion}`
            : finding.packageName;
        parts.push(`(📦 ${pkg})`);
    }

    if (finding.recommendation) {
        parts.push(`💡 ${finding.recommendation}`);
    }

    return parts.join(" ");
}
