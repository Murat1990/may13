// INTENTIONALLY VULNERABLE — DO NOT DEPLOY
const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const axios = require("axios");

const app = express();
app.use(express.json());

// Hardcoded secret (bad)
const JWT_SECRET = "demo-hardcoded-secret-123";

// 1) Command Injection
app.get("/run", (req, res) => {
  const cmd = req.query.cmd || "";
  exec(cmd, (err, stdout, stderr) =>
    res.type("text").send(err ? err.message : (stdout || stderr || "ok"))
  );
});

// 2) Path Traversal
app.get("/file", (req, res) => {
  const name = req.query.name || "";
  try {
    const data = fs.readFileSync("public/" + name, "utf8"); // no sanitization
    res.type("text").send(data);
  } catch (e) {
    res.status(404).send(e.message);
  }
});

// 3) Reflected XSS
app.get("/search", (req, res) => {
  const q = req.query.q || "";
  res.send(`<h1>Results for: ${q}</h1>`); // unsanitized HTML
});

// 4) SSRF
app.get("/proxy", async (req, res) => {
  const url = req.query.url || "";
  try {
    const r = await axios.get(url); // no allowlist/validation
    res.type("text").send(r.data);
  } catch (e) {
    res.status(500).send(e.message);
  }
});

// 5) Dangerous eval
app.get("/calc", (req, res) => {
  const expr = req.query.expr || "";
  try {
    const out = eval(expr); // arbitrary code execution
    res.send(String(out));
  } catch (e) {
    res.status(400).send(e.message);
  }
});

// 6) Secret leak
app.get("/secret", (_req, res) => {
  res.json({ jwtSecret: JWT_SECRET });
});

app.listen(3000, () => console.log("Vuln app at http://localhost:3000"));
