import path from "node:path";
import fs from "node:fs/promises";
import os from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

type GrammarConfig = {
  id: string;
  pkg: string;
  subdir?: string;
  extraDirs?: string[];
  patchScannerInclude?: boolean;
};

const GRAMMARS: GrammarConfig[] = [
  { id: "python", pkg: "tree-sitter-python" },
  { id: "go", pkg: "tree-sitter-go" },
  { id: "java", pkg: "tree-sitter-java" },
  { id: "c-sharp", pkg: "tree-sitter-c-sharp" },
  { id: "ruby", pkg: "tree-sitter-ruby" },
  { id: "php", pkg: "tree-sitter-php", subdir: "php", extraDirs: ["common"], patchScannerInclude: true },
  { id: "rust", pkg: "tree-sitter-rust" },
  { id: "kotlin", pkg: "tree-sitter-kotlin" },
  { id: "swift", pkg: "tree-sitter-swift" },
  { id: "c", pkg: "tree-sitter-c" },
  { id: "cpp", pkg: "tree-sitter-cpp" }
];

async function main() {
  const root = process.cwd();
  const outDir = path.join(root, "assets", "grammars");
  await fs.mkdir(outDir, { recursive: true });

  for (const grammar of GRAMMARS) {
    const basePath = path.join(root, "node_modules", grammar.pkg);
    try {
      await fs.access(basePath);
    } catch {
      console.warn(`Skipping ${grammar.id}: ${grammar.pkg} not installed.`);
      continue;
    }
    const grammarPath = grammar.subdir ? path.join(basePath, grammar.subdir) : basePath;
    const cliPath = path.join(root, "node_modules", ".bin", "tree-sitter");
    const outFile = path.join(outDir, `tree-sitter-${grammar.id}.wasm`);
    try {
      let workingDir = grammarPath;
      let tempDir: string | null = null;
      if (grammar.extraDirs?.length || grammar.patchScannerInclude) {
        tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "opensecurity-grammar-"));
        await fs.cp(grammarPath, tempDir, { recursive: true });
        for (const extra of grammar.extraDirs ?? []) {
          const extraPath = path.join(basePath, extra);
          const targetPath = path.join(tempDir, extra);
          await fs.cp(extraPath, targetPath, { recursive: true });
        }
        if (grammar.patchScannerInclude) {
          const scannerCandidates = [
            path.join(tempDir, "src", "scanner.c"),
            path.join(tempDir, "src", "scanner.cc")
          ];
          for (const scannerPath of scannerCandidates) {
            try {
              const content = await fs.readFile(scannerPath, "utf8");
              const next = content.replace(/\.\.\/\.\.\/common\/scanner\.h/g, "../common/scanner.h");
              if (next !== content) {
                await fs.writeFile(scannerPath, next, "utf8");
              }
            } catch {
              // ignore missing scanner files
            }
          }
        }
        workingDir = tempDir;
      }

      await execFileAsync(cliPath, ["build-wasm"], {
        cwd: workingDir,
        maxBuffer: 20 * 1024 * 1024
      });
      const outputs = (await fs.readdir(workingDir)).filter((file) => file.endsWith(".wasm"));
      if (!outputs.length) {
        throw new Error("No .wasm output found after build.");
      }
      const wasmPath = path.join(workingDir, outputs[0]);
      await fs.copyFile(wasmPath, outFile);
      if (tempDir) {
        await fs.rm(tempDir, { recursive: true, force: true });
      }
      console.log(`Built ${outFile}`);
    } catch (err: any) {
      console.error(`Failed building ${grammar.id}: ${err?.message ?? err}`);
      process.exitCode = 1;
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
