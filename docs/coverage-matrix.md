# Rule Coverage Matrix (Taint Rules)

This matrix tracks which taint rule families are currently available per language. It reflects the **native Tree‑sitter taint rules** in `rules/taint/*.json`.

Legend: ✅ available, ➖ not currently defined.

| Language | SQLi | Command Injection | Path Traversal | SSRF | Unsafe Deserialization | Template XSS | Weak Crypto | Hardcoded Secrets |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Python | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Go | ✅ | ✅ | ✅ | ✅ | ➖ | ✅ | ✅ | ✅ |
| Java | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| C# | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Ruby | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| PHP | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Rust | ✅ | ✅ | ✅ | ✅ | ➖ | ✅ | ✅ | ✅ |
| Kotlin | ✅ | ✅ | ✅ | ✅ | ➖ | ✅ | ✅ | ✅ |
| Swift | ✅ | ✅ | ✅ | ✅ | ➖ | ✅ | ✅ | ✅ |
| C | ➖ | ✅ | ✅ | ➖ | ➖ | ➖ | ✅ | ✅ |
| C++ | ➖ | ✅ | ✅ | ➖ | ➖ | ➖ | ✅ | ✅ |

Notes:
- Deserialization rules are only defined where standard dangerous APIs are common and well‑known.
- C/C++ currently focus on command injection, path traversal, weak crypto, and hardcoded secrets.
