import traverseImport from "@babel/traverse";
import type { File } from "@babel/types";
import * as t from "@babel/types";
import type { OwaspCategory, RuleSeverity } from "./rules.js";

export type PatternFinding = {
  id: string;
  severity: RuleSeverity;
  owasp: OwaspCategory;
  title: string;
  description: string;
  file: string;
  line?: number;
  column?: number;
};

const SECRET_NAME_REGEX = /^(api[-_]?key|secret|token|password|passwd|pwd|private[-_]?key|access[-_]?key|client[-_]?secret)$/i;
const SECRET_VALUE_MIN_LEN = 16;
const SECRET_ENTROPY_THRESHOLD = 3.7;

const SECRET_VALUE_PATTERNS: Array<{ id: string; pattern: RegExp; title: string }> = [
  { id: "secret-aws-access-key", pattern: /AKIA[0-9A-Z]{16}/, title: "Hardcoded AWS Access Key" },
  { id: "secret-github", pattern: /gh[pousr]_[A-Za-z0-9]{20,}/, title: "Hardcoded GitHub Token" },
  { id: "secret-slack", pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/, title: "Hardcoded Slack Token" },
  { id: "secret-stripe", pattern: /sk_live_[A-Za-z0-9]{16,}/, title: "Hardcoded Stripe Secret Key" },
  { id: "secret-google-api", pattern: /AIza[0-9A-Za-z\-_]{35}/, title: "Hardcoded Google API Key" },
  { id: "secret-jwt", pattern: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/, title: "Hardcoded JWT" },
  { id: "secret-private-key", pattern: /-----BEGIN (RSA|EC|DSA|PRIVATE) KEY-----/, title: "Hardcoded Private Key" }
];

const WEAK_HASHES = new Set(["md5", "sha1", "md4"]);
const WEAK_CIPHERS = ["des", "3des", "rc2", "rc4", "bf", "blowfish", "idea"];
const INSECURE_RANDOM_CALLS = new Set(["Math.random", "crypto.pseudoRandomBytes", "pseudoRandomBytes"]);

const DESERIALIZATION_CALLEES = new Set([
  "unserialize",
  "deserialize",
  "serialize.unserialize",
  "serialize.deserialize",
  "yaml.load",
  "YAML.load",
  "jsyaml.load"
]);

export function runPatternDetectors(ast: File, filePath: string): PatternFinding[] {
  const traverse = normalizeTraverse(traverseImport);
  const findings: PatternFinding[] = [];

  const toLoc = (node: t.Node) => {
    const loc = node.loc?.start;
    return {
      line: loc?.line,
      column: typeof loc?.column === "number" ? loc.column + 1 : undefined
    };
  };

  const pushFinding = (finding: PatternFinding) => {
    findings.push(finding);
  };

  const markSecret = (node: t.Node, title: string, description: string, id = "hardcoded-secret") => {
    const loc = toLoc(node);
    pushFinding({
      id,
      severity: "high",
      owasp: "A07:2021 Identification and Authentication Failures",
      title,
      description,
      file: filePath,
      line: loc.line,
      column: loc.column
    });
  };

  const markCrypto = (node: t.Node, title: string, description: string, id = "insecure-crypto") => {
    const loc = toLoc(node);
    pushFinding({
      id,
      severity: "high",
      owasp: "A02:2021 Cryptographic Failures",
      title,
      description,
      file: filePath,
      line: loc.line,
      column: loc.column
    });
  };

  const markDeserialize = (node: t.Node, title: string, description: string, id = "unsafe-deserialization") => {
    const loc = toLoc(node);
    pushFinding({
      id,
      severity: "high",
      owasp: "A08:2021 Software and Data Integrity Failures",
      title,
      description,
      file: filePath,
      line: loc.line,
      column: loc.column
    });
  };

  const getStringValue = (node: t.Expression | t.PrivateName | t.SpreadElement | t.JSXNamespacedName): string | null => {
    if (t.isStringLiteral(node)) return node.value;
    if (t.isTemplateLiteral(node) && node.expressions.length === 0) {
      return node.quasis.map((q) => q.value.cooked ?? "").join("");
    }
    return null;
  };

  const isSecretKeyName = (name: string | null | undefined): boolean => {
    if (!name) return false;
    return SECRET_NAME_REGEX.test(name);
  };

  const isHighEntropySecret = (value: string): boolean => {
    if (value.length < SECRET_VALUE_MIN_LEN) return false;
    return shannonEntropy(value) >= SECRET_ENTROPY_THRESHOLD;
  };

  const matchesSecretValue = (value: string): { id: string; title: string } | null => {
    for (const entry of SECRET_VALUE_PATTERNS) {
      if (entry.pattern.test(value)) return { id: entry.id, title: entry.title };
    }
    return null;
  };

  traverse(ast, {
    VariableDeclarator(path) {
      if (!t.isIdentifier(path.node.id)) return;
      if (!path.node.init) return;
      const value = getStringValue(path.node.init as t.Expression);
      if (!value) return;
      if (value.length < SECRET_VALUE_MIN_LEN) return;

      const name = path.node.id.name;
      const matched = matchesSecretValue(value);
      if (matched) {
        markSecret(path.node.init, matched.title, `Detected ${matched.title.toLowerCase()} in code.`, matched.id);
        return;
      }
      if (isSecretKeyName(name)) {
        markSecret(path.node.init, "Hardcoded Secret", `Hardcoded value assigned to '${name}'.`);
        return;
      }
      if (isHighEntropySecret(value)) {
        markSecret(path.node.init, "Hardcoded Secret", "High-entropy string literal may be a secret.");
      }
    },
    ObjectProperty(path) {
      if (!t.isExpression(path.node.value)) return;
      const value = getStringValue(path.node.value);
      if (!value || value.length < SECRET_VALUE_MIN_LEN) return;

      let keyName: string | null = null;
      if (t.isIdentifier(path.node.key)) keyName = path.node.key.name;
      if (t.isStringLiteral(path.node.key)) keyName = path.node.key.value;

      const matched = matchesSecretValue(value);
      if (matched) {
        markSecret(path.node.value, matched.title, `Detected ${matched.title.toLowerCase()} in object literal.`, matched.id);
        return;
      }
      if (isSecretKeyName(keyName)) {
        markSecret(path.node.value, "Hardcoded Secret", `Hardcoded value for object key '${keyName}'.`);
        return;
      }
      if (isHighEntropySecret(value)) {
        markSecret(path.node.value, "Hardcoded Secret", "High-entropy string literal may be a secret.");
      }
    },
    CallExpression(path) {
      const calleeName = getCalleeName(path.node);
      if (!calleeName) return;

      if (calleeName === "crypto.createHash" || calleeName === "createHash") {
        const arg = path.node.arguments[0];
        if (arg && t.isExpression(arg)) {
          const value = getStringValue(arg);
          if (value && WEAK_HASHES.has(value.toLowerCase())) {
            markCrypto(arg, "Weak Hash Function", `Hash algorithm '${value}' is considered weak.`);
          }
        }
      }

      if (INSECURE_RANDOM_CALLS.has(calleeName)) {
        markCrypto(path.node, "Insecure Randomness", "Math.random or pseudoRandomBytes is not cryptographically secure.");
      }

      if (calleeName === "crypto.createCipher" || calleeName === "createCipher") {
        markCrypto(path.node, "Insecure Cipher API", "crypto.createCipher is deprecated and insecure.");
      }
      if (calleeName === "crypto.createDecipher" || calleeName === "createDecipher") {
        markCrypto(path.node, "Insecure Cipher API", "crypto.createDecipher is deprecated and insecure.");
      }

      if (
        calleeName === "crypto.createCipheriv" ||
        calleeName === "crypto.createDecipheriv" ||
        calleeName === "createCipheriv" ||
        calleeName === "createDecipheriv"
      ) {
        const arg = path.node.arguments[0];
        if (arg && t.isExpression(arg)) {
          const value = getStringValue(arg);
          if (value) {
            const lower = value.toLowerCase();
            const weak = WEAK_CIPHERS.some((alg) => lower.includes(alg)) || lower.includes("-ecb") || lower.endsWith("ecb");
            if (weak) {
              markCrypto(arg, "Weak Cipher Algorithm", `Cipher algorithm '${value}' is considered weak.`);
            }
          }
        }
      }

      if (DESERIALIZATION_CALLEES.has(calleeName)) {
        markDeserialize(path.node, "Unsafe Deserialization", `Call to '${calleeName}' may deserialize untrusted data.`);
      }
    }
  });

  return findings;
}

function getCalleeName(node: t.CallExpression): string | null {
  const callee = node.callee;
  if (t.isIdentifier(callee)) return callee.name;
  if (t.isMemberExpression(callee)) return memberExpressionToString(callee);
  return null;
}

function memberExpressionToString(node: t.MemberExpression): string | null {
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

function shannonEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const ch of value) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  const len = value.length;
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
