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
      { id: "sink-axios-request", name: "axios.request", matcher: { callee: "axios.request" } },
      { id: "sink-got", name: "got", matcher: { callee: "got" } },
      { id: "sink-got-get", name: "got.get", matcher: { callee: "got.get" } },
      { id: "sink-got-post", name: "got.post", matcher: { callee: "got.post" } },
      { id: "sink-undici-request", name: "undici.request", matcher: { callee: "undici.request" } },
      { id: "sink-undici-fetch", name: "undici.fetch", matcher: { callee: "undici.fetch" } },
      { id: "sink-http-get", name: "http.get", matcher: { callee: "http.get" } },
      { id: "sink-https-get", name: "https.get", matcher: { callee: "https.get" } },
      { id: "sink-request", name: "request", matcher: { callee: "request" } },
      { id: "sink-request-get", name: "request.get", matcher: { callee: "request.get" } },
      { id: "sink-request-post", name: "request.post", matcher: { callee: "request.post" } },
      { id: "sink-superagent-get", name: "superagent.get", matcher: { callee: "superagent.get" } },
      { id: "sink-superagent-post", name: "superagent.post", matcher: { callee: "superagent.post" } }
    ],
    sanitizers: [
      { id: "san-sanitizeurl", name: "sanitizeUrl", matcher: { callee: "sanitizeUrl" } },
      { id: "san-validateurl", name: "validateUrl", matcher: { callee: "validateUrl" } },
      { id: "san-encodeuri", name: "encodeURI", matcher: { callee: "encodeURI" } },
      { id: "san-encodeuricomp", name: "encodeURIComponent", matcher: { callee: "encodeURIComponent" } }
    ]
  },
  {
    id: "js-path-traversal",
    name: "Path Traversal",
    description: "Untrusted data reaches filesystem APIs",
    severity: "high",
    owasp: "A01:2021 Broken Access Control",
    sources: [
      { id: "src-getUserInput", name: "getUserInput", matcher: { callee: "getUserInput" } },
      { id: "src-req-param", name: "req.param", matcher: { callee: "req.param" } },
      { id: "src-prompt", name: "prompt", matcher: { callee: "prompt" } },
      { id: "src-readline", name: "readline.question", matcher: { callee: "readline.question" } }
    ],
    sinks: [
      { id: "sink-readfile", name: "fs.readFile", matcher: { callee: "fs.readFile" } },
      { id: "sink-readfilesync", name: "fs.readFileSync", matcher: { callee: "fs.readFileSync" } },
      { id: "sink-writefile", name: "fs.writeFile", matcher: { callee: "fs.writeFile" } },
      { id: "sink-writefilesync", name: "fs.writeFileSync", matcher: { callee: "fs.writeFileSync" } },
      { id: "sink-appendfile", name: "fs.appendFile", matcher: { callee: "fs.appendFile" } },
      { id: "sink-appendfilesync", name: "fs.appendFileSync", matcher: { callee: "fs.appendFileSync" } },
      { id: "sink-createreadstream", name: "fs.createReadStream", matcher: { callee: "fs.createReadStream" } },
      { id: "sink-createwritestream", name: "fs.createWriteStream", matcher: { callee: "fs.createWriteStream" } },
      { id: "sink-readdir", name: "fs.readdir", matcher: { callee: "fs.readdir" } },
      { id: "sink-readdirsync", name: "fs.readdirSync", matcher: { callee: "fs.readdirSync" } },
      { id: "sink-stat", name: "fs.stat", matcher: { callee: "fs.stat" } },
      { id: "sink-statsync", name: "fs.statSync", matcher: { callee: "fs.statSync" } },
      { id: "sink-lstat", name: "fs.lstat", matcher: { callee: "fs.lstat" } },
      { id: "sink-lstatsync", name: "fs.lstatSync", matcher: { callee: "fs.lstatSync" } },
      { id: "sink-rm", name: "fs.rm", matcher: { callee: "fs.rm" } },
      { id: "sink-rmsync", name: "fs.rmSync", matcher: { callee: "fs.rmSync" } },
      { id: "sink-unlink", name: "fs.unlink", matcher: { callee: "fs.unlink" } },
      { id: "sink-unlinksync", name: "fs.unlinkSync", matcher: { callee: "fs.unlinkSync" } },
      { id: "sink-rmdir", name: "fs.rmdir", matcher: { callee: "fs.rmdir" } },
      { id: "sink-rmdirsync", name: "fs.rmdirSync", matcher: { callee: "fs.rmdirSync" } }
    ],
    sanitizers: [
      { id: "san-path-normalize", name: "path.normalize", matcher: { callee: "path.normalize" } },
      { id: "san-path-resolve", name: "path.resolve", matcher: { callee: "path.resolve" } },
      { id: "san-path-join", name: "path.join", matcher: { callee: "path.join" } }
    ]
  },
  {
    id: "js-sqli",
    name: "SQL Injection",
    description: "Untrusted data reaches database query execution",
    severity: "critical",
    owasp: "A03:2021 Injection",
    sources: [
      { id: "src-getUserInput", name: "getUserInput", matcher: { callee: "getUserInput" } },
      { id: "src-req-param", name: "req.param", matcher: { callee: "req.param" } },
      { id: "src-prompt", name: "prompt", matcher: { callee: "prompt" } }
    ],
    sinks: [
      { id: "sink-mysql-query", name: "mysql.query", matcher: { callee: "mysql.query" } },
      { id: "sink-mysql2-query", name: "mysql2.query", matcher: { callee: "mysql2.query" } },
      { id: "sink-pg-query", name: "pg.query", matcher: { callee: "pg.query" } },
      { id: "sink-client-query", name: "client.query", matcher: { callee: "client.query" } },
      { id: "sink-pool-query", name: "pool.query", matcher: { callee: "pool.query" } },
      { id: "sink-connection-query", name: "connection.query", matcher: { callee: "connection.query" } },
      { id: "sink-db-query", name: "db.query", matcher: { callee: "db.query" } },
      { id: "sink-sequelize-query", name: "sequelize.query", matcher: { callee: "sequelize.query" } },
      { id: "sink-knex-raw", name: "knex.raw", matcher: { callee: "knex.raw" } }
    ],
    sanitizers: [
      { id: "san-sql-escape", name: "escape", matcher: { callee: "escape" } },
      { id: "san-sql-escapeid", name: "escapeId", matcher: { callee: "escapeId" } },
      { id: "san-sql-parameterize", name: "parameterize", matcher: { callee: "parameterize" } }
    ]
  },
  {
    id: "js-xss-template",
    name: "XSS (Server Templates)",
    description: "Untrusted data reaches server response rendering",
    severity: "high",
    owasp: "A03:2021 Injection",
    sources: [
      { id: "src-getUserInput", name: "getUserInput", matcher: { callee: "getUserInput" } },
      { id: "src-req-param", name: "req.param", matcher: { callee: "req.param" } },
      { id: "src-prompt", name: "prompt", matcher: { callee: "prompt" } }
    ],
    sinks: [
      { id: "sink-res-send", name: "res.send", matcher: { callee: "res.send" } },
      { id: "sink-res-write", name: "res.write", matcher: { callee: "res.write" } },
      { id: "sink-res-end", name: "res.end", matcher: { callee: "res.end" } },
      { id: "sink-res-render", name: "res.render", matcher: { callee: "res.render" } },
      { id: "sink-reply-send", name: "reply.send", matcher: { callee: "reply.send" } }
    ],
    sanitizers: [
      { id: "san-escape", name: "escape", matcher: { callee: "escape" } },
      { id: "san-encodeuri", name: "encodeURI", matcher: { callee: "encodeURI" } },
      { id: "san-encodeuricomp", name: "encodeURIComponent", matcher: { callee: "encodeURIComponent" } }
    ]
  }
];
