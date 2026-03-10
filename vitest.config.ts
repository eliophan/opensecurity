import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    exclude: ["emsdk/**", "dist/**", "node_modules/**"]
  }
});
