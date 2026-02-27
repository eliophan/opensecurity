import { parse } from "@babel/parser";
import type { File } from "@babel/types";

export type ParsedFile = {
  filePath: string;
  code: string;
  ast: File;
};

export type ParseOptions = {
  sourceType?: "script" | "module";
};

export function parseSource(code: string, filePath: string, options: ParseOptions = {}): ParsedFile {
  const ast = parse(code, {
    sourceType: options.sourceType ?? "module",
    sourceFilename: filePath,
    allowReturnOutsideFunction: true,
    errorRecovery: true,
    plugins: [
      "typescript",
      "jsx",
      "classProperties",
      "classPrivateProperties",
      "decorators-legacy",
      "dynamicImport",
      "importMeta",
      "topLevelAwait"
    ]
  });

  return { filePath, code, ast };
}
