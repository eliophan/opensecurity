import { describe, it, expect } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { scan } from "../src/core/scan.js";

async function createTempDir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "opensecurity-deps-"));
}

describe("dependency scan", () => {
  it("finds CVEs from cache and adds recommendations", async () => {
    const root = await createTempDir();
    const prevConfigHome = process.env.OPENSECURITY_CONFIG_HOME;
    process.env.OPENSECURITY_CONFIG_HOME = path.join(root, ".config");
    const pkg = {
      name: "demo",
      version: "1.0.0",
      dependencies: { "left-pad": "^1.3.0" }
    };
    const lock = {
      name: "demo",
      lockfileVersion: 2,
      packages: {
        "": { name: "demo", version: "1.0.0", dependencies: { "left-pad": "1.3.0" } },
        "node_modules/left-pad": { name: "left-pad", version: "1.3.0" }
      }
    };
    const cache = [
      {
        id: "CVE-2020-0001",
        package: "left-pad",
        ecosystem: "npm",
        affectedRange: ">=1.0.0 <1.3.1",
        fixedVersion: "1.3.1",
        severity: "high",
        description: "Test vulnerability"
      }
    ];

    await fs.writeFile(path.join(root, "package.json"), JSON.stringify(pkg, null, 2));
    await fs.writeFile(path.join(root, "package-lock.json"), JSON.stringify(lock, null, 2));
    await fs.writeFile(path.join(root, "cve-cache.json"), JSON.stringify(cache, null, 2));

    const result = await scan({ cwd: root, cveCachePath: "cve-cache.json" });
    const depFinding = result.findings.find((finding) => finding.cveId === "CVE-2020-0001");
    expect(depFinding).toBeTruthy();
    expect(depFinding?.recommendation).toContain("1.3.1");

    if (prevConfigHome === undefined) {
      delete process.env.OPENSECURITY_CONFIG_HOME;
    } else {
      process.env.OPENSECURITY_CONFIG_HOME = prevConfigHome;
    }
  });

  it("adds simulation data when enabled", async () => {
    const root = await createTempDir();
    const prevConfigHome = process.env.OPENSECURITY_CONFIG_HOME;
    process.env.OPENSECURITY_CONFIG_HOME = path.join(root, ".config");
    await fs.writeFile(
      path.join(root, "package.json"),
      JSON.stringify({ name: "demo", version: "1.0.0", dependencies: { lodash: "4.17.0" } }, null, 2)
    );
    await fs.writeFile(
      path.join(root, "package-lock.json"),
      JSON.stringify(
        {
          name: "demo",
          lockfileVersion: 2,
          packages: {
            "": { name: "demo", version: "1.0.0", dependencies: { lodash: "4.17.0" } },
            "node_modules/lodash": { name: "lodash", version: "4.17.0" }
          }
        },
        null,
        2
      )
    );
    await fs.writeFile(
      path.join(root, "cve-cache.json"),
      JSON.stringify(
        [
          {
            id: "CVE-2021-0002",
            package: "lodash",
            ecosystem: "npm",
            affectedRange: ">=4.0.0 <4.17.21",
            severity: "medium",
            description: "Test vulnerability"
          }
        ],
        null,
        2
      )
    );

    const result = await scan({ cwd: root, cveCachePath: "cve-cache.json", simulate: true });
    const finding = result.findings.find((f) => f.cveId === "CVE-2021-0002");
    expect(finding?.simulation?.payload).toBeTruthy();

    if (prevConfigHome === undefined) {
      delete process.env.OPENSECURITY_CONFIG_HOME;
    } else {
      process.env.OPENSECURITY_CONFIG_HOME = prevConfigHome;
    }
  });
});
