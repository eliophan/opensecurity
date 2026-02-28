// examples/bad-code.js
// This file contains intentional security vulnerabilities for testing purposes.

const db = require("sqlite3");
const express = require("express");
const app = express();

// --- VULNERABILITY: SQL Injection (A03:2021) ---
app.get("/user/:id", (req, res) => {
    const query = `SELECT * FROM users WHERE id = '${req.params.id}'`; // Tainted input
    db.run(query, (err, rows) => {
        res.json(rows);
    });
});

// --- VULNERABILITY: Cross-Site Scripting (XSS) (A03:2021) ---
app.get("/greet/:name", (req, res) => {
    res.send(`<h1>Hello, ${req.params.name}</h1>`); // Tainted input reflected directly
});

// --- VULNERABILITY: Insecure Cryptography (A02:2021) ---
const crypto = require("crypto");
function hashPassword(password) {
    const md5 = crypto.createHash("md5"); // Weak hash algorithm
    return md5.update(password).digest("hex");
}

app.listen(3000, () => console.log("Test app running on port 3000"));
