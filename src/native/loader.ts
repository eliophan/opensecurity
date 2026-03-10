import path from "node:path";
import fs from "node:fs/promises";
import { createRequire } from "node:module";
import type { LanguageConfig } from "./languages.js";

type TreeSitterModule = {
  init: () => Promise<void>;
  Language: { load: (path: string) => Promise<any> };
  Parser: new () => { setLanguage: (lang: any) => void; parse: (source: string) => any };
};

let treeSitter: TreeSitterModule | null = null;
let treeSitterInit: Promise<void> | null = null;

export type ParsedTree = {
  tree: any;
  source: string;
  language: LanguageConfig;
};

async function ensureTreeSitter(): Promise<TreeSitterModule> {
  if (treeSitter) return treeSitter;
  const mod: any = await import("web-tree-sitter");
  const resolved: TreeSitterModule = {
    init: mod.init?.bind(mod),
    Language: mod.Language,
    Parser: mod.Parser
  };
  treeSitter = resolved;
  if (!treeSitterInit) {
    treeSitterInit = resolved.init();
  }
  await treeSitterInit;
  return resolved;
}

async function loadNativeLanguage(lang: LanguageConfig): Promise<any | null> {
  try {
    const require = createRequire(import.meta.url);
    const Parser = require("tree-sitter");
    const Lang = require(lang.nativeModule);
    const parser = new Parser();
    parser.setLanguage(Lang);
    return { parser, type: "native" };
  } catch {
    return null;
  }
}

async function loadWasmLanguage(lang: LanguageConfig, baseDir: string): Promise<any | null> {
  const mod = await ensureTreeSitter();
  const wasmPath = path.join(baseDir, "assets", "grammars", lang.wasmFile);
  try {
    await fs.access(wasmPath);
  } catch {
    return null;
  }
  const language = await mod.Language.load(wasmPath);
  const parser = new mod.Parser();
  parser.setLanguage(language);
  return { parser, type: "wasm" };
}

export async function parseWithTreeSitter(
  source: string,
  lang: LanguageConfig,
  baseDir: string
): Promise<ParsedTree | null> {
  const native = await loadNativeLanguage(lang);
  if (native) {
    const tree = native.parser.parse(source);
    return { tree, source, language: lang };
  }
  const wasm = await loadWasmLanguage(lang, baseDir);
  if (wasm) {
    const tree = wasm.parser.parse(source);
    return { tree, source, language: lang };
  }
  return null;
}
