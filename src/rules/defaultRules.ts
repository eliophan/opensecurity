import type { OwaspRule } from "../analysis/rules.js";

export const DEFAULT_RULES: OwaspRule[] = [
  {
    id: "js-eval-injection",
    name: "Eval Injection",
    description: "Untrusted data reaches eval or Function",
    severity: "high",
    owasp: "A03:2021 Injection",
    sources: [
      { id: "src-getUserInput", name: "getUserInput", matcher: { callee: "getUserInput" } },
      { id: "src-req-param", name: "req.param", matcher: { callee: "req.param" } },
      { id: "src-prompt", name: "prompt", matcher: { callee: "prompt" } },
      { id: "src-readline", name: "readline.question", matcher: { callee: "readline.question" } }
    ],
    sinks: [
      { id: "sink-eval", name: "eval", matcher: { callee: "eval" } },
      { id: "sink-function", name: "Function", matcher: { callee: "Function" } }
    ],
    sanitizers: [
      { id: "san-sanitize", name: "sanitize", matcher: { callee: "sanitize" } },
      { id: "san-escape", name: "escape", matcher: { callee: "escape" } },
      { id: "san-validator-escape", name: "validator.escape", matcher: { callee: "validator.escape" } }
    ]
  },
  {
    id: "js-command-injection",
    name: "Command Injection",
    description: "Untrusted data reaches child_process execution",
    severity: "critical",
    owasp: "A03:2021 Injection",
    sources: [
      { id: "src-getUserInput", name: "getUserInput", matcher: { callee: "getUserInput" } },
      { id: "src-req-param", name: "req.param", matcher: { callee: "req.param" } },
      { id: "src-prompt", name: "prompt", matcher: { callee: "prompt" } }
    ],
    sinks: [
      { id: "sink-exec", name: "child_process.exec", matcher: { callee: "child_process.exec" } },
      { id: "sink-execsync", name: "child_process.execSync", matcher: { callee: "child_process.execSync" } },
      { id: "sink-spawn", name: "child_process.spawn", matcher: { callee: "child_process.spawn" } },
      { id: "sink-spawnsync", name: "child_process.spawnSync", matcher: { callee: "child_process.spawnSync" } },
      { id: "sink-execfile", name: "child_process.execFile", matcher: { callee: "child_process.execFile" } },
      { id: "sink-execfilesync", name: "child_process.execFileSync", matcher: { callee: "child_process.execFileSync" } }
    ],
    sanitizers: [
      { id: "san-shellescape", name: "shellescape", matcher: { callee: "shellescape" } },
      { id: "san-escapeshellarg", name: "escapeShellArg", matcher: { callee: "escapeShellArg" } }
    ]
  },
  {
    id: "js-ssrf",
    name: "Server-Side Request Forgery",
    description: "Untrusted data reaches network request",
    severity: "high",
    owasp: "A10:2021 Server-Side Request Forgery",
    sources: [
      { id: "src-getUserInput", name: "getUserInput", matcher: { callee: "getUserInput" } },
      { id: "src-req-param", name: "req.param", matcher: { callee: "req.param" } },
      { id: "src-prompt", name: "prompt", matcher: { callee: "prompt" } }
    ],
    sinks: [
      { id: "sink-fetch", name: "fetch", matcher: { callee: "fetch" } },
      { id: "sink-axios", name: "axios", matcher: { callee: "axios" } },
      { id: "sink-axios-get", name: "axios.get", matcher: { callee: "axios.get" } },
      { id: "sink-axios-post", name: "axios.post", matcher: { callee: "axios.post" } },
      { id: "sink-http-get", name: "http.get", matcher: { callee: "http.get" } },
      { id: "sink-https-get", name: "https.get", matcher: { callee: "https.get" } },
      { id: "sink-request", name: "request", matcher: { callee: "request" } }
    ],
    sanitizers: [
      { id: "san-sanitizeurl", name: "sanitizeUrl", matcher: { callee: "sanitizeUrl" } },
      { id: "san-validateurl", name: "validateUrl", matcher: { callee: "validateUrl" } },
      { id: "san-encodeuri", name: "encodeURI", matcher: { callee: "encodeURI" } },
      { id: "san-encodeuricomp", name: "encodeURIComponent", matcher: { callee: "encodeURIComponent" } }
    ]
  }
];
