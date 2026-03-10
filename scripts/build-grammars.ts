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
  { id: "php", pkg: "tree-sitter-php" },
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

  try {
    await execFileAsync("tree-sitter", ["--version"]);
  } catch {
    console.error("tree-sitter CLI not found. Install with: npm install -D tree-sitter-cli");
    process.exitCode = 1;
    return;
  }

  for (const grammar of GRAMMARS) {
    const grammarPath = path.join(root, "node_modules", grammar.pkg);
    const outFile = path.join(outDir, `tree-sitter-${grammar.id}.wasm`);
    try {
      await execFileAsync("tree-sitter", ["build-wasm", grammarPath, "-o", outFile], {
        cwd: root,
        maxBuffer: 20 * 1024 * 1024
      });
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
