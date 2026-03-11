import type { CallMatcher } from "../analysis/taint.js";
import type { LanguageConfig } from "./languages.js";
import type { NativeRule, NativeRuleSet } from "./rules.js";

export type NativeFinding = {
  ruleId: string;
  ruleTitle: string;
  severity: NativeRule["severity"];
  owasp: NativeRule["owasp"];
  file: string;
  line?: number;
  column?: number;
  message: string;
};

type TNode = {
  type: string;
  startIndex: number;
  endIndex: number;
  startPosition?: { row: number; column: number };
  namedChildren?: TNode[];
  childForFieldName?: (name: string) => TNode | null;
};

function getNodeText(node: TNode, source: string): string {
  return source.slice(node.startIndex, node.endIndex);
}

function normalizeTraverseNode(node: any): TNode {
  return node as TNode;
}

function matchesCallee(name: string, matcher: CallMatcher): boolean {
  if (matcher.callee) {
    const match = matcher.callee;
    if (Array.isArray(match) && match.includes(name)) return true;
    if (match === name) return true;
  }
  if (matcher.calleePrefix) {
    const match = matcher.calleePrefix;
    if (Array.isArray(match) && match.some((prefix) => name.startsWith(prefix))) return true;
    if (typeof match === "string" && name.startsWith(match)) return true;
  }
  if (matcher.calleePattern) {
    const match = matcher.calleePattern;
    const patterns = Array.isArray(match) ? match : [match];
    return patterns.some((pattern) => matchGlob(name, pattern));
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

function getNodeNames(node: TNode, lang: LanguageConfig, source: string): string[] {
  if (lang.identifierNodes.includes(node.type)) {
    return [getNodeText(node, source)];
  }
  if (lang.memberNodes.includes(node.type)) {
    const objectNode = pickField(node, lang.memberObjectFields);
    const propNode = pickField(node, lang.memberPropertyFields);
    const objectNames = objectNode ? getNodeNames(objectNode, lang, source) : [];
    const propName = propNode ? (getNodeNames(propNode, lang, source)[0] ?? getNodeText(propNode, source)) : null;
    if (!propName) return [];
    const fullNames = objectNames.length ? objectNames.map((name) => `${name}.${propName}`) : [propName];
    const variants = new Set<string>();
    for (const fullName of fullNames) {
      const parts = fullName.split(".");
      for (let i = 0; i < parts.length; i += 1) {
        variants.add(parts.slice(i).join("."));
      }
    }
    return Array.from(variants);
  }
  return [];
}

function pickField(node: TNode, fields: string[]): TNode | null {
  for (const field of fields) {
    const child = node.childForFieldName?.(field);
    if (child) return normalizeTraverseNode(child);
  }
  return null;
}

function getCallNames(node: TNode, lang: LanguageConfig, source: string): string[] {
  const callee =
    pickField(node, lang.callCalleeFields) ??
    (node.namedChildren?.[0] ? normalizeTraverseNode(node.namedChildren[0]) : null);
  if (!callee) return [];
  const names = getNodeNames(callee, lang, source);
  if (names.length) return names;
  return [getNodeText(callee, source)];
}

function getCallArguments(node: TNode, lang: LanguageConfig): TNode[] {
  const argNode = pickField(node, lang.callArgumentFields);
  if (argNode?.namedChildren?.length) {
    return argNode.namedChildren.map(normalizeTraverseNode);
  }
  return [];
}

function getAssignmentSides(node: TNode, lang: LanguageConfig): { left: TNode | null; right: TNode | null } {
  const left = pickField(node, lang.assignmentLeftFields);
  const right = pickField(node, lang.assignmentRightFields);
  return { left: left ? normalizeTraverseNode(left) : null, right: right ? normalizeTraverseNode(right) : null };
}

function isStringNode(node: TNode, lang: LanguageConfig): boolean {
  return lang.stringNodes.includes(node.type);
}

function walk(node: TNode, fn: (n: TNode) => void) {
  fn(node);
  const children = node.namedChildren ?? [];
  for (const child of children) {
    walk(normalizeTraverseNode(child), fn);
  }
}

function findIdentifiers(node: TNode, lang: LanguageConfig, source: string): string[] {
  const names: string[] = [];
  walk(node, (n) => {
    const name = getNodeNames(n, lang, source)[0];
    if (name && lang.identifierNodes.includes(n.type)) names.push(name);
  });
  return names;
}

function matchesAnyCallee(names: string[], matcher: CallMatcher): boolean {
  for (const name of names) {
    if (matchesCallee(name, matcher)) return true;
  }
  return false;
}

function indexToLineColumn(source: string, index: number): { line: number; column: number } {
  const before = source.slice(0, Math.max(0, index));
  const lines = before.split("\n");
  const line = lines.length;
  const column = lines[lines.length - 1]?.length ?? 0;
  return { line, column: column + 1 };
}

export function runNativeTaint(
  tree: any,
  source: string,
  lang: LanguageConfig,
  ruleSet: NativeRuleSet,
  filePath: string
): NativeFinding[] {
  const root = normalizeTraverseNode(tree.rootNode ?? tree);
  const findings: NativeFinding[] = [];
  const taintedVarsStack: Array<Set<string>> = [new Set()];
  const taintedExpressions = new WeakSet<TNode>();
  const sanitizedVarsStack: Array<Set<string>> = [new Set()];
  const sanitizedExpressions = new WeakSet<TNode>();

  const pushScope = () => taintedVarsStack.push(new Set());
  const popScope = () => taintedVarsStack.pop();
  const currentScope = () => taintedVarsStack[taintedVarsStack.length - 1];
  const taint = (name: string) => currentScope()?.add(name);
  const untaint = (name: string) => currentScope()?.delete(name);
  const isTainted = (name: string) => currentScope()?.has(name) ?? false;
  const pushSanitizedScope = () => sanitizedVarsStack.push(new Set());
  const popSanitizedScope = () => sanitizedVarsStack.pop();
  const currentSanitizedScope = () => sanitizedVarsStack[sanitizedVarsStack.length - 1];
  const sanitize = (name: string) => currentSanitizedScope()?.add(name);
  const unsanitize = (name: string) => currentSanitizedScope()?.delete(name);
  const isSanitized = (name: string) => currentSanitizedScope()?.has(name) ?? false;

  const valueIsSanitized = (node: TNode, rule: NativeRule): boolean => {
    if (sanitizedExpressions.has(node)) return true;
    const nodeNames = getNodeNames(node, lang, source);
    const primaryName = nodeNames[0];
    if (lang.identifierNodes.includes(node.type) && primaryName) {
      return isSanitized(primaryName);
    }
    if (lang.memberNodes.includes(node.type) && primaryName) {
      return isSanitized(primaryName);
    }
    if (lang.callNodes.includes(node.type)) {
      const calleeNames = getCallNames(node, lang, source);
      if (calleeNames.length && rule.sanitizers?.some((san) => matchesAnyCallee(calleeNames, san.matcher))) {
        sanitizedExpressions.add(node);
        return true;
      }
    }
    const children = node.namedChildren ?? [];
    return children.some((child) => valueIsSanitized(normalizeTraverseNode(child), rule));
  };

  const valueIsTainted = (node: TNode, rule: NativeRule): boolean => {
    if (valueIsSanitized(node, rule)) return false;
    if (taintedExpressions.has(node)) return true;
    const nodeNames = getNodeNames(node, lang, source);
    if (nodeNames.length && rule.sources?.some((src) => matchesAnyCallee(nodeNames, src.matcher))) {
      return true;
    }
    const primaryName = nodeNames[0];
    if (lang.identifierNodes.includes(node.type) && primaryName) {
      return isTainted(primaryName);
    }
    if (lang.memberNodes.includes(node.type) && primaryName) {
      return isTainted(primaryName);
    }
    if (lang.callNodes.includes(node.type)) {
      const calleeNames = getCallNames(node, lang, source);
      if (calleeNames.length) {
        if (rule.sanitizers?.some((san) => matchesAnyCallee(calleeNames, san.matcher))) {
          sanitizedExpressions.add(node);
          return false;
        }
        if (rule.sources?.some((src) => matchesAnyCallee(calleeNames, src.matcher))) return true;
      }
    }
    const children = node.namedChildren ?? [];
    return children.some((child) => valueIsTainted(normalizeTraverseNode(child), rule));
  };

  const handleAssignment = (node: TNode, rule: NativeRule) => {
    const { left, right } = getAssignmentSides(node, lang);
    if (!left || !right) return;
    const targetNames = findIdentifiers(left, lang, source);
    const sanitized = valueIsSanitized(right, rule);
    const tainted = valueIsTainted(right, rule);
    for (const name of targetNames) {
      if (sanitized) {
        untaint(name);
        sanitize(name);
      } else if (tainted) {
        taint(name);
        taintedExpressions.add(right);
        unsanitize(name);
      } else {
        untaint(name);
        unsanitize(name);
      }
    }
  };

  const reportFinding = (rule: NativeRule, node: TNode, message: string) => {
    const loc = node.startPosition;
    const fallback = loc ? null : indexToLineColumn(source, node.startIndex);
    findings.push({
      ruleId: rule.id,
      ruleTitle: rule.title,
      severity: rule.severity,
      owasp: rule.owasp,
      file: filePath,
      line: loc ? loc.row + 1 : fallback?.line,
      column: loc ? loc.column + 1 : fallback?.column,
      message
    });
  };

  const runRule = (rule: NativeRule) => {
    if (rule.kind === "secret") {
      const pattern = rule.literalPattern ? new RegExp(rule.literalPattern, "i") : null;
      if (!pattern) return;
      walk(root, (node) => {
        if (!isStringNode(node, lang)) return;
        const text = getNodeText(node, source);
        if (pattern.test(text)) {
          reportFinding(rule, node, rule.title);
        }
      });
      return;
    }

    if (rule.kind === "direct") {
      const matcher: CallMatcher = {
        callee: rule.callee,
        calleePrefix: rule.calleePrefix,
        calleePattern: rule.calleePattern
      };
      walk(root, (node) => {
        if (!lang.callNodes.includes(node.type)) return;
        const names = getCallNames(node, lang, source);
        if (names.length && matchesAnyCallee(names, matcher)) {
          reportFinding(rule, node, rule.title);
        }
      });
      return;
    }

    walk(root, (node) => {
      if (lang.assignmentNodes.includes(node.type)) {
        handleAssignment(node, rule);
        return;
      }

      if (lang.callNodes.includes(node.type)) {
        const calleeNames = getCallNames(node, lang, source);
        if (!calleeNames.length) return;
        const sink = rule.sinks?.find((candidate) => matchesAnyCallee(calleeNames, candidate.matcher));
        if (!sink) return;
        const args = getCallArguments(node, lang);
        const hasTainted = args.some((arg) => valueIsTainted(arg, rule));
        if (hasTainted) {
          reportFinding(rule, node, `Tainted data reaches sink ${sink.name}`);
        }
      }
    });
  };

  for (const rule of ruleSet.rules) {
    taintedVarsStack.length = 0;
    taintedVarsStack.push(new Set());
    sanitizedVarsStack.length = 0;
    sanitizedVarsStack.push(new Set());
    runRule(rule);
  }

  return findings;
}
