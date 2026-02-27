import traverseImport, { NodePath } from "@babel/traverse";
import type {
  File,
  CallExpression,
  Identifier,
  FunctionDeclaration,
  FunctionExpression,
  ArrowFunctionExpression,
  ObjectMethod,
  ClassMethod,
  VariableDeclarator,
  AssignmentExpression,
  UpdateExpression,
  MemberExpression
} from "@babel/types";
import * as t from "@babel/types";

export type ImportGraph = Map<string, Set<string>>;
export type CallGraph = Map<string, Set<string>>;

export type FunctionInfo = {
  id: string;
  name: string;
  file: string;
  loc?: { line: number; column: number };
  params: string[];
  isAsync: boolean;
  kind: "function" | "arrow" | "method" | "module";
};

export type FunctionMap = Map<string, FunctionInfo>;

export type DataFlowNode = {
  id: string;
  name: string;
  file: string;
  loc?: { line: number; column: number };
};

export type DataFlowEdge = {
  from: DataFlowNode;
  to: DataFlowNode;
  kind: "data";
};

export type DataFlowGraph = {
  nodes: DataFlowNode[];
  edges: DataFlowEdge[];
};

export function buildImportGraph(ast: File, filePath: string): ImportGraph {
  const traverse = normalizeTraverse(traverseImport);
  const graph: ImportGraph = new Map();
  graph.set(filePath, new Set());

  traverse(ast, {
    ImportDeclaration(path) {
      const source = path.node.source.value;
      graph.get(filePath)?.add(source);
    },
    CallExpression(path) {
      const callee = path.node.callee;
      if (!t.isIdentifier(callee) || callee.name !== "require") return;
      const arg = path.node.arguments[0];
      if (!t.isStringLiteral(arg)) return;
      graph.get(filePath)?.add(arg.value);
    }
  });

  return graph;
}

export function buildFunctionMap(ast: File, filePath: string): FunctionMap {
  const traverse = normalizeTraverse(traverseImport);
  const map: FunctionMap = new Map();

  const registerFunction = (
    name: string,
    node:
      | FunctionDeclaration
      | FunctionExpression
      | ArrowFunctionExpression
      | ObjectMethod
      | ClassMethod,
    kind: FunctionInfo["kind"]
  ) => {
    const loc = node.loc?.start ? { line: node.loc.start.line, column: node.loc.start.column } : undefined;
    const params = node.params.map((param) => (t.isIdentifier(param) ? param.name : "<pattern>"));
    const id = `${filePath}:${name}:${loc?.line ?? 0}`;
    map.set(id, {
      id,
      name,
      file: filePath,
      loc,
      params,
      isAsync: Boolean((node as FunctionDeclaration).async),
      kind
    });
  };

  const moduleId = `${filePath}:<module>:0`;
  map.set(moduleId, {
    id: moduleId,
    name: "<module>",
    file: filePath,
    loc: { line: 0, column: 0 },
    params: [],
    isAsync: false,
    kind: "module"
  });

  traverse(ast, {
    FunctionDeclaration(path) {
      const name = path.node.id?.name ?? "<anonymous>";
      registerFunction(name, path.node, "function");
    },
    FunctionExpression(path) {
      const name = inferFunctionName(path) ?? "<anonymous>";
      registerFunction(name, path.node, "function");
    },
    ArrowFunctionExpression(path) {
      const name = inferFunctionName(path) ?? "<anonymous>";
      registerFunction(name, path.node, "arrow");
    },
    ObjectMethod(path) {
      const name = getPropertyName(path.node.key) ?? "<anonymous>";
      registerFunction(name, path.node, "method");
    },
    ClassMethod(path) {
      const name = getPropertyName(path.node.key) ?? "<anonymous>";
      registerFunction(name, path.node, "method");
    }
  });

  return map;
}

export function buildCallGraph(ast: File, filePath: string, functions: FunctionMap): CallGraph {
  const traverse = normalizeTraverse(traverseImport);
  const graph: CallGraph = new Map();
  const fnStack: string[] = [];

  const ensure = (id: string) => {
    if (!graph.has(id)) graph.set(id, new Set());
  };

  const moduleId = [...functions.values()].find((f) => f.kind === "module" && f.file === filePath)?.id;
  const rootId = moduleId ?? `${filePath}:<module>:0`;

  const pushFn = (id: string) => {
    fnStack.push(id);
    ensure(id);
  };

  const popFn = () => {
    fnStack.pop();
  };

  const currentFn = () => fnStack[fnStack.length - 1] ?? rootId;

  traverse(ast, {
    Program: {
      enter() {
        pushFn(rootId);
      },
      exit() {
        popFn();
      }
    },
    FunctionDeclaration: {
      enter(path) {
        const name = path.node.id?.name ?? "<anonymous>";
        const id = findFunctionId(functions, filePath, name, path.node.loc?.start.line);
        pushFn(id ?? `${filePath}:${name}:${path.node.loc?.start.line ?? 0}`);
      },
      exit() {
        popFn();
      }
    },
    FunctionExpression: {
      enter(path) {
        const name = inferFunctionName(path) ?? "<anonymous>";
        const id = findFunctionId(functions, filePath, name, path.node.loc?.start.line);
        pushFn(id ?? `${filePath}:${name}:${path.node.loc?.start.line ?? 0}`);
      },
      exit() {
        popFn();
      }
    },
    ArrowFunctionExpression: {
      enter(path) {
        const name = inferFunctionName(path) ?? "<anonymous>";
        const id = findFunctionId(functions, filePath, name, path.node.loc?.start.line);
        pushFn(id ?? `${filePath}:${name}:${path.node.loc?.start.line ?? 0}`);
      },
      exit() {
        popFn();
      }
    },
    ObjectMethod: {
      enter(path) {
        const name = getPropertyName(path.node.key) ?? "<anonymous>";
        const id = findFunctionId(functions, filePath, name, path.node.loc?.start.line);
        pushFn(id ?? `${filePath}:${name}:${path.node.loc?.start.line ?? 0}`);
      },
      exit() {
        popFn();
      }
    },
    ClassMethod: {
      enter(path) {
        const name = getPropertyName(path.node.key) ?? "<anonymous>";
        const id = findFunctionId(functions, filePath, name, path.node.loc?.start.line);
        pushFn(id ?? `${filePath}:${name}:${path.node.loc?.start.line ?? 0}`);
      },
      exit() {
        popFn();
      }
    },
    CallExpression(path) {
      const caller = currentFn();
      const callee = getCalleeName(path.node);
      if (!callee) return;
      ensure(caller);
      graph.get(caller)?.add(callee);
    }
  });

  return graph;
}

export function buildDataFlowGraph(ast: File, filePath: string): DataFlowGraph {
  const traverse = normalizeTraverse(traverseImport);
  const nodes: DataFlowNode[] = [];
  const edges: DataFlowEdge[] = [];
  const scopes: Array<Map<string, DataFlowNode>> = [];

  const pushScope = () => scopes.push(new Map());
  const popScope = () => scopes.pop();
  const currentScope = () => scopes[scopes.length - 1];

  const recordDef = (name: string, node: t.Node) => {
    const loc = node.loc?.start ? { line: node.loc.start.line, column: node.loc.start.column } : undefined;
    const dataNode: DataFlowNode = {
      id: `${filePath}:${name}:${loc?.line ?? 0}:${loc?.column ?? 0}`,
      name,
      file: filePath,
      loc
    };
    nodes.push(dataNode);
    currentScope()?.set(name, dataNode);
  };

  const recordUse = (name: string, node: t.Node) => {
    const loc = node.loc?.start ? { line: node.loc.start.line, column: node.loc.start.column } : undefined;
    const useNode: DataFlowNode = {
      id: `${filePath}:${name}:${loc?.line ?? 0}:${loc?.column ?? 0}:use`,
      name,
      file: filePath,
      loc
    };
    nodes.push(useNode);
    const defNode = currentScope()?.get(name);
    if (defNode) {
      edges.push({ from: defNode, to: useNode, kind: "data" });
    }
  };

  traverse(ast, {
    Program: {
      enter() {
        pushScope();
      },
      exit() {
        popScope();
      }
    },
    Function: {
      enter() {
        pushScope();
      },
      exit() {
        popScope();
      }
    },
    VariableDeclarator(path) {
      const id = path.node.id;
      if (t.isIdentifier(id)) {
        recordDef(id.name, id);
      }
    },
    AssignmentExpression(path) {
      const left = path.node.left;
      if (t.isIdentifier(left)) {
        recordDef(left.name, left);
      }
    },
    UpdateExpression(path) {
      const arg = path.node.argument;
      if (t.isIdentifier(arg)) {
        recordUse(arg.name, arg);
        recordDef(arg.name, arg);
      }
    },
    Identifier(path) {
      if (!path.isReferencedIdentifier()) return;
      recordUse(path.node.name, path.node);
    }
  });

  return { nodes, edges };
}

function getCalleeName(node: CallExpression): string | null {
  const callee = node.callee;
  if (t.isIdentifier(callee)) return callee.name;
  if (t.isMemberExpression(callee)) return memberExpressionToString(callee);
  return null;
}

function memberExpressionToString(node: MemberExpression): string | null {
  if (node.computed) return null;
  const object = node.object;
  const property = node.property;
  const objectName = t.isIdentifier(object)
    ? object.name
    : t.isMemberExpression(object)
      ? memberExpressionToString(object)
      : null;
  if (!objectName) return null;
  if (!t.isIdentifier(property)) return null;
  return `${objectName}.${property.name}`;
}

function inferFunctionName(path: NodePath<FunctionExpression | ArrowFunctionExpression>): string | null {
  const parent = path.parentPath;
  if (parent?.isVariableDeclarator() && t.isIdentifier(parent.node.id)) return parent.node.id.name;
  if (parent?.isAssignmentExpression() && t.isIdentifier(parent.node.left)) return parent.node.left.name;
  if (parent?.isObjectProperty()) return getPropertyName(parent.node.key);
  return null;
}

function getPropertyName(key: t.Expression | t.PrivateName): string | null {
  if (t.isIdentifier(key)) return key.name;
  if (t.isStringLiteral(key)) return key.value;
  return null;
}

function findFunctionId(
  functions: FunctionMap,
  filePath: string,
  name: string,
  line?: number | null
): string | null {
  for (const info of functions.values()) {
    if (info.file !== filePath) continue;
    if (info.name !== name) continue;
    if (line && info.loc?.line !== line) continue;
    return info.id;
  }
  return null;
}

function normalizeTraverse(
  value: typeof traverseImport
): typeof traverseImport {
  return (value as unknown as { default?: typeof traverseImport }).default ?? value;
}
