import { describe, it, expect } from "vitest";
import { scoreRisk } from "../src/engines/deps/scoring.js";

const baseCve = {
  id: "CVE-TEST",
  package: "demo",
  ecosystem: "npm" as const
};

describe("risk scoring", () => {
  it("uses CVSS score when present", () => {
    const score = scoreRisk({ ...baseCve, cvssScore: 9.8 });
    expect(score.score).toBeGreaterThan(90);
    expect(score.severity).toBe("critical");
  });

  it("adjusts for exploitability and data sensitivity", () => {
    const score = scoreRisk({ ...baseCve, severity: "medium", exploitability: "high" }, { dataSensitivity: "high" });
    expect(score.score).toBeGreaterThan(40);
  });
});
