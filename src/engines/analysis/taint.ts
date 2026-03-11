import traverseImport from "@babel/traverse";
import type { File, CallExpression, Identifier, MemberExpression, OptionalMemberExpression } from "@babel/types";
import * as t from "@babel/types";

export type CallMatcher = {
  callee?: string | string[];
  calleePattern?: string | string[];
  calleePrefix?: string | string[];
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
  column?: number;
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
    const calleeNames = getCalleeNames(node);
    if (!calleeNames.length) return null;
    return endpoints.find((endpoint) => matchesAnyCallee(calleeNames, endpoint.matcher));
  };

  const isSanitizerCall = (node: CallExpression) => matchEndpoint(node, rules.sanitizers);
  const isSourceCall = (node: CallExpression) => matchEndpoint(node, rules.sources);
  const isSinkCall = (node: CallExpression) => matchEndpoint(node, rules.sinks);

  const valueIsTainted = (node: t.Node): boolean => {
    if (taintedExpressions.has(node)) return true;
    if (t.isIdentifier(node)) return isTainted(node.name);
    if (t.isMemberExpression(node)) {
      return t.isExpression(node.object) ? valueIsTainted(node.object) : false;
    }
    if (t.isCallExpression(node)) {
      if (isSanitizerCall(node)) return false;
      if (isSourceCall(node)) return true;
      return false;
    }
    if (t.isBinaryExpression(node) || t.isLogicalExpression(node)) {
      return valueIsTainted(node.left) || valueIsTainted(node.right);
    }
    if (t.isConditionalExpression(node)) {
      return valueIsTainted(node.test) || valueIsTainted(node.consequent) || valueIsTainted(node.alternate);
    }
    if (t.isTemplateLiteral(node)) {
      return node.expressions.some((expr) => valueIsTainted(expr));
    }
    if (t.isArrayExpression(node)) {
      return node.elements.some((el) => (t.isExpression(el) ? valueIsTainted(el) : false));
    }
    if (t.isObjectExpression(node)) {
      return node.properties.some((prop) => {
        if (t.isObjectProperty(prop) && t.isExpression(prop.value)) return valueIsTainted(prop.value);
        if (t.isSpreadElement(prop) && t.isExpression(prop.argument)) return valueIsTainted(prop.argument);
        return false;
      });
    }
    if (t.isUnaryExpression(node)) {
      return t.isExpression(node.argument) ? valueIsTainted(node.argument) : false;
    }
    if (t.isSequenceExpression(node)) {
      return node.expressions.some((expr) => valueIsTainted(expr));
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
        column: typeof loc?.column === "number" ? loc.column + 1 : undefined,
        message: `Tainted data reaches sink ${sink.name}`
      });
    }
  });

  return findings;
}

function getCalleeNames(node: CallExpression): string[] {
  const callee = node.callee;
  if (t.isIdentifier(callee)) return [callee.name];
  if (t.isMemberExpression(callee) || t.isOptionalMemberExpression(callee)) {
    return memberExpressionToNames(callee);
  }
  return [];
}

function memberExpressionToNames(node: MemberExpression | OptionalMemberExpression): string[] {
  const chain = extractMemberChain(node);
  if (!chain.length) return [];
  const variants = new Set<string>();
  for (let i = 0; i < chain.length; i += 1) {
    variants.add(chain.slice(i).join("."));
  }
  return Array.from(variants);
}

function extractMemberChain(node: MemberExpression | OptionalMemberExpression): string[] {
  if (node.computed) {
    if (t.isStringLiteral(node.property)) {
      const objectNames = extractMemberObjectNames(node.object);
      return objectNames.length ? [...objectNames, node.property.value] : [];
    }
    return [];
  }
  const objectNames = extractMemberObjectNames(node.object);
  if (!t.isIdentifier(node.property)) return [];
  return objectNames.length ? [...objectNames, node.property.name] : [];
}

function extractMemberObjectNames(object: t.Expression | t.PrivateName): string[] {
  if (t.isIdentifier(object)) return [object.name];
  if (t.isThisExpression(object)) return ["this"];
  if (t.isMemberExpression(object) || t.isOptionalMemberExpression(object)) return extractMemberChain(object);
  return [];
}

function matchesAnyCallee(calleeNames: string[], matcher: CallMatcher): boolean {
  for (const calleeName of calleeNames) {
    if (matchesCallee(calleeName, matcher)) return true;
  }
  return false;
}

function matchesCallee(calleeName: string, matcher: CallMatcher): boolean {
  if (matcher.callee) {
    const match = matcher.callee;
    if (Array.isArray(match) && match.includes(calleeName)) return true;
    if (match === calleeName) return true;
  }
  if (matcher.calleePrefix) {
    const match = matcher.calleePrefix;
    if (Array.isArray(match) && match.some((prefix) => calleeName.startsWith(prefix))) return true;
    if (typeof match === "string" && calleeName.startsWith(match)) return true;
  }
  if (matcher.calleePattern) {
    const match = matcher.calleePattern;
    if (Array.isArray(match) && match.some((pattern) => matchGlob(calleeName, pattern))) return true;
    if (typeof match === "string" && matchGlob(calleeName, match)) return true;
  }
  return false;
}

function matchGlob(value: string, pattern: string): boolean {
  if (pattern === value) return true;
  try {
    const picomatch = require("picomatch");
    const isMatch = picomatch(pattern, { nocase: false, dot: true });
    return isMatch(value);
  } catch {
    return false;
  }
}

function normalizeTraverse(
  value: typeof traverseImport
): typeof traverseImport {
  return (value as unknown as { default?: typeof traverseImport }).default ?? value;
}
