import path from "node:path";
import fs from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const GRAMMARS = [
  { id: "python", pkg: "tree-sitter-python" },
  { id: "go", pkg: "tree-sitter-go" },
  { id: "java", pkg: "tree-sitter-java" },
  { id: "c-sharp", pkg: "tree-sitter-c-sharp" },
  { id: "ruby", pkg: "tree-sitter-ruby" },
  { id: "php", pkg: "tree-sitter-php", subdir: "php" },
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
      await execFileAsync(cliPath, ["build-wasm"], {
        cwd: grammarPath,
        maxBuffer: 20 * 1024 * 1024
      });
      const outputs = (await fs.readdir(grammarPath)).filter((file) => file.endsWith(".wasm"));
      if (!outputs.length) {
        throw new Error("No .wasm output found after build.");
      }
      const wasmPath = path.join(grammarPath, outputs[0]);
      await fs.copyFile(wasmPath, outFile);
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
