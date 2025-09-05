# app.py  (INTENTIONALLY VULNERABLE — DO NOT DEPLOY)
from flask import Flask, request
import sqlite3, os

app = Flask(__name__)

# Hardcoded secret (bad)
API_KEY = "sk_demo_hardcoded_123"

# Insecure DB (no auth, shared connection)
db = sqlite3.connect("db.sqlite", check_same_thread=False)
db.execute("CREATE TABLE IF NOT EXISTS users(u TEXT, p TEXT)")
db.execute("INSERT INTO users(u,p) VALUES('admin','admin123')")  # weak creds
db.commit()

# 1) SQL Injection: string-concat query
@app.get("/login")
def login():
    u = request.args.get("u", "")
    p = request.args.get("p", "")
    q = f"SELECT * FROM users WHERE u='{u}' AND p='{p}'"  # vulnerable
    row = db.execute(q).fetchone()
    return ("Welcome " + row[0]) if row else ("Invalid", 401)

# 2) Command Injection: unsanitized shell command
@app.get("/run")
def run():
    cmd = request.args.get("cmd", "")
    return os.popen(cmd).read()  # vulnerable

# 3) Reflected XSS: unsanitized HTML output
@app.get("/search")
def search():
    q = request.args.get("q", "")
    return f"<h1>Results for: {q}</h1>"  # vulnerable

# 4) Path Traversal: reads arbitrary files
@app.get("/file")
def file():
    path = request.args.get("path", "")
    try:
        return open(path, "r").read()  # vulnerable
    except Exception as e:
        return str(e), 404

# 5) Secret leak endpoint
@app.get("/secret")
def secret():
    return {"api_key": API_KEY}

if __name__ == "__main__":
    app.run(debug=True)
