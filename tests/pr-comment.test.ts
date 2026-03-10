import { describe, it, expect } from "vitest";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

function runPrComment(inputJson: string): string {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pr-comment-test-"));
    const inputFile = path.join(tmpDir, "scan-results.json");
    fs.writeFileSync(inputFile, inputJson, "utf8");
    try {
        const result = execFileSync(
            "npx",
            ["tsx", path.resolve("src/ui/pr-comment.ts"), inputFile],
            { cwd: path.resolve("."), encoding: "utf8", timeout: 10000 }
        );
        return result;
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
}

describe("PR comment reporter", () => {
    it("renders no-findings message", () => {
        const output = runPrComment(JSON.stringify({ findings: [] }));
        expect(output).toContain("OpenSecurity Scan Results");
        expect(output).toContain("No security findings detected");
    });

    it("renders findings grouped by severity", () => {
        const input = JSON.stringify({
            findings: [
                {
                    id: "CVE-2024-001",
                    severity: "critical",
                    title: "RCE in foo",
                    description: "Remote code execution",
                    file: "package.json",
                    category: "dependency",
                    packageName: "foo",
                    packageVersion: "1.0.0",
                    recommendation: "Upgrade to 2.0.0"
                },
                {
                    id: "js-eval-injection",
                    severity: "high",
                    title: "Eval injection",
                    description: "Tainted data reaches eval",
                    file: "src/handler.ts",
                    line: 42,
                    owasp: "A03:2021 Injection",
                    category: "code"
                },
                {
                    id: "CVE-2024-002",
                    severity: "low",
                    title: "Info disclosure in bar",
                    description: "Leaks version info",
                    file: "package.json",
                    category: "dependency",
                    packageName: "bar"
                }
            ]
        });

        const output = runPrComment(input);
        expect(output).toContain("CRITICAL");
        expect(output).toContain("HIGH");
        expect(output).toContain("LOW");
        expect(output).toContain("RCE in foo");
        expect(output).toContain("`foo@1.0.0`");
        expect(output).toContain("Upgrade to 2.0.0");
        expect(output).toContain("Eval injection");
        expect(output).toContain("`src/handler.ts:42`");
        expect(output).toContain("critical/high severity");
    });

    it("handles plain text input gracefully", () => {
        const output = runPrComment("No findings.");
        expect(output).toContain("No security findings detected");
    });
});
