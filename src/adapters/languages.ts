const normalizeExt = (ext: string) => ext.toLowerCase();

export const PYTHON_EXTS = new Set([".py", ".pyw"].map(normalizeExt));
export const GO_EXTS = new Set([".go"].map(normalizeExt));
export const RUBY_EXTS = new Set([".rb"].map(normalizeExt));
export const PHP_EXTS = new Set([".php", ".phtml", ".php5", ".php7", ".phps"].map(normalizeExt));
export const RUST_EXTS = new Set([".rs"].map(normalizeExt));
export const JAVA_EXTS = new Set([".java"].map(normalizeExt));
export const CSHARP_EXTS = new Set([".cs"].map(normalizeExt));
export const KOTLIN_EXTS = new Set([".kt", ".kts"].map(normalizeExt));
export const SWIFT_EXTS = new Set([".swift", ".m", ".mm"].map(normalizeExt));
export const C_EXTS = new Set([".c", ".h"].map(normalizeExt));
export const CPP_EXTS = new Set([".cpp", ".hpp", ".cc", ".cxx", ".hh", ".hxx"].map(normalizeExt));

export const SEMGREP_EXTS = new Set([
  ...JAVA_EXTS,
  ...CSHARP_EXTS,
  ...PHP_EXTS,
  ...RUST_EXTS,
  ...KOTLIN_EXTS,
  ...SWIFT_EXTS,
  ...C_EXTS,
  ...CPP_EXTS
].map(normalizeExt));

export function matchesExtension(filePath: string, extensions: Set<string>): boolean {
  const idx = filePath.lastIndexOf(".");
  if (idx === -1) return false;
  const ext = filePath.slice(idx).toLowerCase();
  return extensions.has(ext);
}
