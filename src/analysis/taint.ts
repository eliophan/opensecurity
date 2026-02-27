import traverseImport from "@babel/traverse";
import type { File, CallExpression, Identifier, MemberExpression } from "@babel/types";
import * as t from "@babel/types";

export type CallMatcher = {
  callee: string | string[];
};

export type TaintEndpoint = {
  id: string;
  name: string;
  matcher: CallMatcher;
};

export type TaintRuleSet = {
  sources: TaintEndpoint[];
  sinks: TaintEndpoint[];
  sanitizers: TaintEndpoint[];
};

export type TaintFinding = {
  sourceId: string;
  sinkId: string;
  file: string;
  line?: number;
  message: string;
};

export function runTaintAnalysis(ast: File, filePath: string, rules: TaintRuleSet): TaintFinding[] {
  const traverse = normalizeTraverse(traverseImport);
  const findings: TaintFinding[] = [];
  const taintedVarsStack: Array<Set<string>> = [];
  const taintedExpressions = new WeakSet<t.Node>();

  const pushScope = () => taintedVarsStack.push(new Set());
  const popScope = () => taintedVarsStack.pop();
  const currentScope = () => taintedVarsStack[taintedVarsStack.length - 1];

  const isTainted = (name: string) => currentScope()?.has(name) ?? false;
  const taint = (name: string) => currentScope()?.add(name);
  const untaint = (name: string) => currentScope()?.delete(name);

  const matchEndpoint = (node: CallExpression, endpoints: TaintEndpoint[]) => {
    const calleeName = getCalleeName(node);
    if (!calleeName) return null;
    return endpoints.find((endpoint) => {
      const match = endpoint.matcher.callee;
      if (Array.isArray(match)) return match.includes(calleeName);
      return match === calleeName;
    });
  };

  const isSanitizerCall = (node: CallExpression) => matchEndpoint(node, rules.sanitizers);
  const isSourceCall = (node: CallExpression) => matchEndpoint(node, rules.sources);
  const isSinkCall = (node: CallExpression) => matchEndpoint(node, rules.sinks);

  const valueIsTainted = (node: t.Node): boolean => {
    if (taintedExpressions.has(node)) return true;
    if (t.isIdentifier(node)) return isTainted(node.name);
    if (t.isCallExpression(node)) {
      if (isSanitizerCall(node)) return false;
      if (isSourceCall(node)) return true;
    }
    return false;
  };

  const handleAssignment = (id: Identifier, value: t.Node) => {
    if (t.isCallExpression(value)) {
      if (isSanitizerCall(value)) {
        untaint(id.name);
        return;
      }
      if (isSourceCall(value)) {
        taint(id.name);
        taintedExpressions.add(value);
        return;
      }
    }

    if (valueIsTainted(value)) {
      taint(id.name);
    } else {
      untaint(id.name);
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
    VariableDeclarator(path: import("@babel/traverse").NodePath<t.VariableDeclarator>) {
      if (!path.node.init) return;
      if (!t.isIdentifier(path.node.id)) return;
      handleAssignment(path.node.id, path.node.init);
    },
    AssignmentExpression(path: import("@babel/traverse").NodePath<t.AssignmentExpression>) {
      const left = path.node.left;
      if (!t.isIdentifier(left)) return;
      handleAssignment(left, path.node.right);
    },
    CallExpression(path: import("@babel/traverse").NodePath<t.CallExpression>) {
      const sink = isSinkCall(path.node);
      if (!sink) return;
      const args = path.node.arguments;
      const hasTaintedArg = args.some((arg) => Boolean(t.isExpression(arg) && valueIsTainted(arg)));
      if (!hasTaintedArg) return;
      const loc = path.node.loc?.start;
      findings.push({
        sourceId: "tainted",
        sinkId: sink.id,
        file: filePath,
        line: loc?.line,
        message: `Tainted data reaches sink ${sink.name}`
      });
    }
  });

  return findings;
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

function normalizeTraverse(
  value: typeof traverseImport
): typeof traverseImport {
  return (value as unknown as { default?: typeof traverseImport }).default ?? value;
}
