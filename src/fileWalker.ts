import fs from "node:fs/promises";
import path from "node:path";
import picomatch from "picomatch";

export type FileWalkerOptions = {
  include: string[];
  exclude: string[];
};

export async function walkFiles(rootDir: string, options: FileWalkerOptions): Promise<string[]> {
  const includeMatchers = options.include.map((p) => picomatch(p, { dot: true }));
  const excludeMatchers = options.exclude.map((p) => picomatch(p, { dot: true }));
  const results: string[] = [];

  async function visit(currentDir: string): Promise<void> {
    const entries = await fs.readdir(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const relPath = path.relative(rootDir, fullPath).split(path.sep).join("/");

      if (excludeMatchers.some((m) => m(relPath))) {
        continue;
      }

      if (entry.isDirectory()) {
        await visit(fullPath);
        continue;
      }

      if (includeMatchers.length === 0 || includeMatchers.some((m) => m(relPath))) {
        results.push(fullPath);
      }
    }
  }

  await visit(rootDir);
  return results;
}
