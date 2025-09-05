# app.py  (INTENTIONALLY VULNERABLE)
from flask import Flask, request
import sqlite3, os

app = Flask(__name__)
db = sqlite3.connect('db.sqlite', check_same_thread=False)
db.execute("CREATE TABLE IF NOT EXISTS users(u TEXT, p TEXT)")
db.commit()

# 1) SQL Injection (string concatenation)
@app.get("/login")
def login():
    u = request.args.get("u", "")
    p = request.args.get("p", "")
    q = f"SELECT * FROM users WHERE u='{u}' AND p='{p}'"
    try:
        row = db.execute(q).fetchone()
        return ("Welcome " + row[0]) if row else ("Invalid", 401)
    except Exception as e:
        return str(e), 500

# 2) Command Injection (unsanitized shell)
@app.get("/run")
def run():
    cmd = request.args.get("cmd", "")
    return os.popen(cmd).read()  # user-controlled command

# 3) Reflected XSS (unsanitized HTML output)
@app.get("/search")
def search():
    q = request.args.get("q", "")
    return f"<h1>Results for: {q}</h1>"  # echoes raw input

if __name__ == "__main__":
    app.run(debug=True)
