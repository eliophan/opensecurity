import { describe, it, expect } from "vitest";
import { filterAdapters } from "../src/adapters/runner.js";
import { matchesExtension, PYTHON_EXTS, GO_EXTS, SEMGREP_EXTS } from "../src/adapters/languages.js";

describe("adapter selection", () => {
  it("filters adapters by allow list", () => {
    const selected = filterAdapters(["bandit", "gosec"]);
    const ids = selected.map((adapter) => adapter.id).sort();
    expect(ids).toEqual(["bandit", "gosec"]);
  });
});

describe("language extension matching", () => {
  it("matches python extensions", () => {
    expect(matchesExtension("main.py", PYTHON_EXTS)).toBe(true);
    expect(matchesExtension("main.go", PYTHON_EXTS)).toBe(false);
  });

  it("matches go extensions", () => {
    expect(matchesExtension("main.go", GO_EXTS)).toBe(true);
    expect(matchesExtension("main.rs", GO_EXTS)).toBe(false);
  });

  it("matches semgrep extensions for multi-lang", () => {
    expect(matchesExtension("app.java", SEMGREP_EXTS)).toBe(true);
    expect(matchesExtension("lib.rs", SEMGREP_EXTS)).toBe(true);
    expect(matchesExtension("script.py", SEMGREP_EXTS)).toBe(false);
  });
});
