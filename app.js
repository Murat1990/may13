// app.js — INTENTIONALLY VULNERABLE (for scanner testing only)
const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");

const app = express();

// 1) Command Injection: runs user-supplied shell
app.get("/run", (req, res) => {
  const cmd = req.query.cmd || "";
  exec(cmd, (err, out, errout) => res.type("text").send(err ? err.message : (out || errout || "ok")));
});

// 2) Path Traversal: reads arbitrary files
app.get("/file", (req, res) => {
  const p = req.query.path || "";
  try { res.type("text").send(fs.readFileSync(p, "utf8")); }
  catch (e) { res.status(404).send(e.message); }
});

// 3) Reflected XSS: echoes unsanitized input
app.get("/search", (req, res) => {
  const q = req.query.q || "";
  res.send(`<h1>Results for: ${q}</h1>`);
});

app.listen(3000, () => console.log("Vuln app at http://localhost:3000"));
/*
Run (local only):
  npm init -y && npm i express
  node app.js
*/
