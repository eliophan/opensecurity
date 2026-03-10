export type NativeLanguageId =
  | "python"
  | "go"
  | "java"
  | "csharp"
  | "ruby"
  | "php"
  | "rust"
  | "kotlin"
  | "swift"
  | "c"
  | "cpp";

export type LanguageConfig = {
  id: NativeLanguageId;
  name: string;
  extensions: string[];
  wasmFile: string;
  nativeModule: string;
  callNodes: string[];
  callCalleeFields: string[];
  callArgumentFields: string[];
  assignmentNodes: string[];
  assignmentLeftFields: string[];
  assignmentRightFields: string[];
  memberNodes: string[];
  memberObjectFields: string[];
  memberPropertyFields: string[];
  identifierNodes: string[];
  stringNodes: string[];
};

const LANGUAGES: LanguageConfig[] = [
  {
    id: "python",
    name: "Python",
    extensions: [".py", ".pyw"],
    wasmFile: "tree-sitter-python.wasm",
    nativeModule: "tree-sitter-python",
    callNodes: ["call"],
    callCalleeFields: ["function"],
    callArgumentFields: ["arguments"],
    assignmentNodes: ["assignment"],
    assignmentLeftFields: ["left"],
    assignmentRightFields: ["right"],
    memberNodes: ["attribute"],
    memberObjectFields: ["object"],
    memberPropertyFields: ["attribute"],
    identifierNodes: ["identifier"],
    stringNodes: ["string", "string_literal"]
  },
  {
    id: "go",
    name: "Go",
    extensions: [".go"],
    wasmFile: "tree-sitter-go.wasm",
    nativeModule: "tree-sitter-go",
    callNodes: ["call_expression"],
    callCalleeFields: ["function"],
    callArgumentFields: ["arguments"],
    assignmentNodes: ["assignment_statement"],
    assignmentLeftFields: ["left"],
    assignmentRightFields: ["right"],
    memberNodes: ["selector_expression"],
    memberObjectFields: ["operand"],
    memberPropertyFields: ["field"],
    identifierNodes: ["identifier"],
    stringNodes: ["interpreted_string_literal", "raw_string_literal"]
  },
  {
    id: "java",
    name: "Java",
    extensions: [".java"],
    wasmFile: "tree-sitter-java.wasm",
    nativeModule: "tree-sitter-java",
    callNodes: ["method_invocation"],
    callCalleeFields: ["name", "object"],
    callArgumentFields: ["arguments"],
    assignmentNodes: ["assignment_expression"],
    assignmentLeftFields: ["left"],
    assignmentRightFields: ["right"],
    memberNodes: ["field_access"],
    memberObjectFields: ["object"],
    memberPropertyFields: ["field"],
    identifierNodes: ["identifier"],
    stringNodes: ["string_literal"]
  },
  {
    id: "csharp",
    name: "C#",
    extensions: [".cs"],
    wasmFile: "tree-sitter-c-sharp.wasm",
    nativeModule: "tree-sitter-c-sharp",
    callNodes: ["invocation_expression"],
    callCalleeFields: ["expression"],
    callArgumentFields: ["argument_list"],
    assignmentNodes: ["assignment_expression"],
    assignmentLeftFields: ["left"],
    assignmentRightFields: ["right"],
    memberNodes: ["member_access_expression"],
    memberObjectFields: ["expression"],
    memberPropertyFields: ["name"],
    identifierNodes: ["identifier"],
    stringNodes: ["string_literal"]
  },
  {
    id: "ruby",
    name: "Ruby",
    extensions: [".rb"],
    wasmFile: "tree-sitter-ruby.wasm",
    nativeModule: "tree-sitter-ruby",
    callNodes: ["call", "command_call"],
    callCalleeFields: ["method", "receiver"],
    callArgumentFields: ["arguments"],
    assignmentNodes: ["assignment"],
    assignmentLeftFields: ["left"],
    assignmentRightFields: ["right"],
    memberNodes: ["call"],
    memberObjectFields: ["receiver"],
    memberPropertyFields: ["method"],
    identifierNodes: ["identifier", "constant"],
    stringNodes: ["string", "string_literal"]
  },
  {
    id: "php",
    name: "PHP",
    extensions: [".php", ".phtml", ".php5", ".php7", ".phps"],
    wasmFile: "tree-sitter-php.wasm",
    nativeModule: "tree-sitter-php",
    callNodes: ["function_call_expression", "member_call_expression", "scoped_call_expression"],
    callCalleeFields: ["name", "function", "member", "scope"],
    callArgumentFields: ["arguments"],
    assignmentNodes: ["assignment_expression"],
    assignmentLeftFields: ["left"],
    assignmentRightFields: ["right"],
    memberNodes: ["member_call_expression", "scoped_call_expression"],
    memberObjectFields: ["object", "scope"],
    memberPropertyFields: ["name", "member"],
    identifierNodes: ["name", "variable_name", "identifier"],
    stringNodes: ["string", "string_literal"]
  },
  {
    id: "rust",
    name: "Rust",
    extensions: [".rs"],
    wasmFile: "tree-sitter-rust.wasm",
    nativeModule: "tree-sitter-rust",
    callNodes: ["call_expression", "macro_invocation"],
    callCalleeFields: ["function", "macro"],
    callArgumentFields: ["arguments", "token_tree"],
    assignmentNodes: ["assignment_expression", "let_declaration"],
    assignmentLeftFields: ["left", "pattern"],
    assignmentRightFields: ["right", "value"],
    memberNodes: ["field_expression"],
    memberObjectFields: ["value"],
    memberPropertyFields: ["field"],
    identifierNodes: ["identifier", "self"],
    stringNodes: ["string_literal", "raw_string_literal"]
  },
  {
    id: "kotlin",
    name: "Kotlin",
    extensions: [".kt", ".kts"],
    wasmFile: "tree-sitter-kotlin.wasm",
    nativeModule: "tree-sitter-kotlin",
    callNodes: ["call_expression", "primary_expression"],
    callCalleeFields: ["callee", "reference"],
    callArgumentFields: ["value_arguments"],
    assignmentNodes: ["assignment"],
    assignmentLeftFields: ["left"],
    assignmentRightFields: ["right"],
    memberNodes: ["navigation_expression"],
    memberObjectFields: ["receiver"],
    memberPropertyFields: ["selector"],
    identifierNodes: ["identifier"],
    stringNodes: ["string_literal"]
  },
  {
    id: "swift",
    name: "Swift",
    extensions: [".swift"],
    wasmFile: "tree-sitter-swift.wasm",
    nativeModule: "tree-sitter-swift",
    callNodes: ["function_call_expression"],
    callCalleeFields: ["function"],
    callArgumentFields: ["argument_clause"],
    assignmentNodes: ["assignment_expression"],
    assignmentLeftFields: ["left"],
    assignmentRightFields: ["right"],
    memberNodes: ["member_access_expression"],
    memberObjectFields: ["object"],
    memberPropertyFields: ["name"],
    identifierNodes: ["identifier"],
    stringNodes: ["string_literal"]
  },
  {
    id: "c",
    name: "C",
    extensions: [".c", ".h"],
    wasmFile: "tree-sitter-c.wasm",
    nativeModule: "tree-sitter-c",
    callNodes: ["call_expression"],
    callCalleeFields: ["function"],
    callArgumentFields: ["arguments"],
    assignmentNodes: ["assignment_expression", "init_declarator"],
    assignmentLeftFields: ["left", "declarator"],
    assignmentRightFields: ["right", "value"],
    memberNodes: ["field_expression"],
    memberObjectFields: ["argument"],
    memberPropertyFields: ["field"],
    identifierNodes: ["identifier"],
    stringNodes: ["string_literal"]
  },
  {
    id: "cpp",
    name: "C++",
    extensions: [".cpp", ".hpp", ".cc", ".cxx", ".hh", ".hxx"],
    wasmFile: "tree-sitter-cpp.wasm",
    nativeModule: "tree-sitter-cpp",
    callNodes: ["call_expression"],
    callCalleeFields: ["function"],
    callArgumentFields: ["arguments"],
    assignmentNodes: ["assignment_expression", "init_declarator"],
    assignmentLeftFields: ["left", "declarator"],
    assignmentRightFields: ["right", "value"],
    memberNodes: ["field_expression", "qualified_identifier"],
    memberObjectFields: ["scope", "argument"],
    memberPropertyFields: ["name", "field"],
    identifierNodes: ["identifier"],
    stringNodes: ["string_literal"]
  }
];

export function getNativeLanguages(): LanguageConfig[] {
  return [...LANGUAGES];
}

export function getLanguageByExtension(filePath: string): LanguageConfig | null {
  const lower = filePath.toLowerCase();
  for (const lang of LANGUAGES) {
    if (lang.extensions.some((ext) => lower.endsWith(ext))) return lang;
  }
  return null;
}
