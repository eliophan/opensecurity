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

function getNodeName(node: TNode, lang: LanguageConfig, source: string): string | null {
  if (lang.identifierNodes.includes(node.type)) {
    return getNodeText(node, source);
  }
  if (lang.memberNodes.includes(node.type)) {
    const objectNode = pickField(node, lang.memberObjectFields);
    const propNode = pickField(node, lang.memberPropertyFields);
    const objectName = objectNode ? getNodeName(objectNode, lang, source) ?? getNodeText(objectNode, source) : null;
    const propName = propNode ? getNodeName(propNode, lang, source) ?? getNodeText(propNode, source) : null;
    if (objectName && propName) return `${objectName}.${propName}`;
    if (propName) return propName;
  }
  return null;
}

function pickField(node: TNode, fields: string[]): TNode | null {
  for (const field of fields) {
    const child = node.childForFieldName?.(field);
    if (child) return normalizeTraverseNode(child);
  }
  return null;
}

function getCallName(node: TNode, lang: LanguageConfig, source: string): string | null {
  const callee =
    pickField(node, lang.callCalleeFields) ??
    (node.namedChildren?.[0] ? normalizeTraverseNode(node.namedChildren[0]) : null);
  if (!callee) return null;
  return getNodeName(callee, lang, source) ?? getNodeText(callee, source);
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
    const name = getNodeName(n, lang, source);
    if (name && lang.identifierNodes.includes(n.type)) names.push(name);
  });
  return names;
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

  const pushScope = () => taintedVarsStack.push(new Set());
  const popScope = () => taintedVarsStack.pop();
  const currentScope = () => taintedVarsStack[taintedVarsStack.length - 1];
  const taint = (name: string) => currentScope()?.add(name);
  const untaint = (name: string) => currentScope()?.delete(name);
  const isTainted = (name: string) => currentScope()?.has(name) ?? false;

  const valueIsTainted = (node: TNode, rule: NativeRule): boolean => {
    if (taintedExpressions.has(node)) return true;
    const nodeName = getNodeName(node, lang, source);
    if (nodeName && rule.sources?.some((src) => matchesCallee(nodeName, src.matcher))) {
      return true;
    }
    if (lang.identifierNodes.includes(node.type) && nodeName) {
      return isTainted(nodeName);
    }
    if (lang.memberNodes.includes(node.type) && nodeName) {
      return isTainted(nodeName);
    }
    if (lang.callNodes.includes(node.type)) {
      const calleeName = getCallName(node, lang, source);
      if (calleeName) {
        if (rule.sanitizers?.some((san) => matchesCallee(calleeName, san.matcher))) return false;
        if (rule.sources?.some((src) => matchesCallee(calleeName, src.matcher))) return true;
      }
    }
    const children = node.namedChildren ?? [];
    return children.some((child) => valueIsTainted(normalizeTraverseNode(child), rule));
  };

  const handleAssignment = (node: TNode, rule: NativeRule) => {
    const { left, right } = getAssignmentSides(node, lang);
    if (!left || !right) return;
    const targetNames = findIdentifiers(left, lang, source);
    const tainted = valueIsTainted(right, rule);
    for (const name of targetNames) {
      if (tainted) {
        taint(name);
        taintedExpressions.add(right);
      } else {
        untaint(name);
      }
    }
  };

  const reportFinding = (rule: NativeRule, node: TNode, message: string) => {
    const loc = node.startPosition;
    findings.push({
      ruleId: rule.id,
      ruleTitle: rule.title,
      severity: rule.severity,
      owasp: rule.owasp,
      file: filePath,
      line: loc ? loc.row + 1 : undefined,
      column: loc ? loc.column + 1 : undefined,
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
        const name = getCallName(node, lang, source);
        if (name && matchesCallee(name, matcher)) {
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
        const calleeName = getCallName(node, lang, source);
        if (!calleeName) return;
        const sink = rule.sinks?.find((candidate) => matchesCallee(calleeName, candidate.matcher));
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
    runRule(rule);
  }

  return findings;
}
