import { describe, it, expect } from "vitest";
import { buildPromptWithContext, createBatches, groupFilesByModule } from "../src/core/scan.js";

describe("ai multi-agent batching", () => {
  it("groups files by module depth", () => {
    const files = [
      "src/auth/login.ts",
      "src/auth/refresh.ts",
      "src/billing/invoices/create.ts",
      "packages/core/index.ts",
      "apps/web/main.tsx",
      "README.md"
    ];
    const grouped = groupFilesByModule(files, 2);
    expect(grouped.get("src/auth")?.length).toBe(2);
    expect(grouped.get("src/billing/invoices")?.length).toBe(1);
    expect(grouped.get("packages/core")?.length).toBe(1);
    expect(grouped.get("apps/web")?.length).toBe(1);
    expect(grouped.get("root")?.length).toBe(1);
  });

  it("creates batches without losing files", () => {
    const files = ["src/a.ts", "src/b.ts", "src/c.ts"];
    const grouped = groupFilesByModule(files, 2);
    const batches = createBatches(grouped, 2);
    const flattened = batches.flatMap((b) => b.files).sort();
    expect(flattened).toEqual(files.sort());
  });

  it("adds leader context to prompts", () => {
    const prompt = buildPromptWithContext("src/a.ts", "const x = 1;", 1, 1, "README: demo");
    expect(prompt).toContain("Context Summary:");
    expect(prompt).toContain("README: demo");
  });
});
