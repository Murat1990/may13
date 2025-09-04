// Intentionally vulnerable demo app (DO NOT USE IN PRODUCTION)
// Purpose: Provide insecure patterns for testing security review tools.
// Vulnerabilities included (by route):
// - SQL Injection: /login
// - Reflected XSS: /search
// - Command Injection: /run
// - Path Traversal: /file
// - SSRF: /fetch
// - Weak Password Hashing (MD5): /signup
// - Insecure Randomness: /token
// - Hardcoded Secret: API_KEY constant

const express = require('express');
const axios = require('axios');
const md5 = require('md5');
const { exec } = require('child_process');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();

// Hardcoded secret (bad practice)
const API_KEY = "sk-demo-hardcoded-12345";

const app = express();
app.use(express.json());

// Insecure SQLite setup
const db = new sqlite3.Database('db.sqlite');
db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
  db.run("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'admin123')");
});

// SQL Injection: concatenates user input into the query
app.get('/login', (req, res) => {
  const { username = '', password = '' } = req.query;
  const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  db.get(query, (err, row) => {
    if (err) return res.status(500).send('DB error: ' + err.message);
    if (row) return res.send('Welcome ' + row.username);
    res.status(401).send('Invalid credentials');
  });
});

// Reflected XSS: echoes unsanitized input into HTML
app.get('/search', (req, res) => {
  const { q = '' } = req.query;
  res.send("<h1>Results for: " + q + "</h1>");
});

// Command Injection: passes user-controlled string to exec
app.get('/run', (req, res) => {
  const { cmd = '' } = req.query;
  exec(cmd, (error, stdout, stderr) => {
    if (error) return res.status(500).send("Error: " + error.message);
    res.type('text').send(stdout || stderr || 'Done');
  });
});

// Path Traversal: reads arbitrary filesystem paths from user input
app.get('/file', (req, res) => {
  const { path = '' } = req.query;
  fs.readFile(path, 'utf8', (err, data) => {
    if (err) return res.status(404).send('Cannot read file: ' + err.message);
    res.type('text').send(data);
  });
});

// SSRF: fetches user-supplied URL without validation
app.get('/fetch', async (req, res) => {
  const { url = '' } = req.query;
  try {
    const r = await axios.get(url);
    res.type('text').send(r.data);
  } catch (e) {
    res.status(500).send('Fetch failed: ' + e.message);
  }
});

// Weak Password Hashing (MD5) and unsalted storage
app.post('/signup', (req, res) => {
  const { username = '', password = '' } = req.body || {};
  const hash = md5(password); // weak hashing
  db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hash], function(err) {
    if (err) return res.status(500).send('Insert failed: ' + err.message);
    res.json({ id: this.lastID, username });
  });
});

// Insecure randomness for tokens
app.get('/token', (req, res) => {
  const token = Math.random().toString(36).slice(2); // predictable
  res.json({ token });
});

// Leaks a secret value (anti-pattern)
app.get('/secret', (req, res) => {
  res.json({ apiKey: API_KEY });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('Vulnerable app listening on http://localhost:' + PORT);
});
