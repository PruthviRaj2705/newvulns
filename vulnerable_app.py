"""
vulnerable_app.py -- INTENTIONALLY VULNERABLE TEST TARGET

Purpose: give the Shift-Left pipeline (SonarQube SAST, Trivy SCA/secrets,
Gemini remediation) something real to find and fix.

DO NOT DEPLOY. DO NOT EXPOSE TO A NETWORK. Every secret below is fake.
"""
import base64
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, jsonify, redirect, render_template, request

app = Flask(__name__)

# --- [Secrets] hardcoded credentials (all fake) -----------------------------
app.secret_key = "super-secret-key-123"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
GITHUB_TOKEN = "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
DB_PASSWORD = "admin123"

# --- In-memory database ------------------------------------------------------
db = sqlite3.connect(":memory:", check_same_thread=False)
db.executescript(
    """
    CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
    CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
    """
)
db.execute(
    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
    # [Weak crypto] MD5 password hashing
    ("admin", hashlib.md5(b"admin123").hexdigest(), "admin"),
)
db.execute(
    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
    ("guest", hashlib.md5(b"guest").hexdigest(), "user"),
)
db.executemany(
    "INSERT INTO products (name, price) VALUES (?, ?)",
    [("Notebook", 4.5), ("Desk lamp", 22.0), ("Headphones", 59.9)],
)
db.commit()


@app.route("/")
def index():
    return render_template("index.html")


# [SQL injection] string-built query
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = hashlib.md5(data.get("password", "").encode()).hexdigest()
    query = (
        "SELECT id, username, role FROM users WHERE username = '"
        + username
        + "' AND password = '"
        + password
        + "'"
    )
    try:
        row = db.execute(query).fetchone()
    except sqlite3.Error as error:
        return jsonify({"ok": False, "error": str(error), "query": query}), 500
    if row:
        return jsonify({"ok": True, "user": {"id": row[0], "username": row[1], "role": row[2]}})
    return jsonify({"ok": False, "error": "Invalid credentials"}), 401


# [SQL injection + reflected XSS] unescaped input in query and in HTML
@app.route("/api/search")
def search():
    q = request.args.get("q", "")
    try:
        rows = db.execute(
            f"SELECT name, price FROM products WHERE name LIKE '%{q}%'"
        ).fetchall()
    except sqlite3.Error as error:
        return f"<p>Database error: {error}</p>", 500
    items = "".join(f"<li>{name}: ${price}</li>" for name, price in rows)
    return f"<h4>Results for {q}</h4><ul>{items}</ul>"


# [Command injection] user input passed to a shell
@app.route("/api/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.run(
        "ping -c 1 " + host, shell=True, capture_output=True, text=True, timeout=10
    )
    return jsonify({"output": result.stdout + result.stderr})


# [Path traversal] no check that the path stays inside ./files
@app.route("/api/file")
def read_file():
    name = request.args.get("name", "notes.txt")
    try:
        with open(os.path.join("files", name), "r", encoding="utf-8", errors="replace") as f:
            return jsonify({"content": f.read()})
    except OSError as error:
        return jsonify({"error": str(error)}), 404


# [Code injection] eval on user input
@app.route("/api/calc", methods=["POST"])
def calc():
    expr = (request.get_json(silent=True) or {}).get("expr", "")
    try:
        return jsonify({"result": str(eval(expr))})
    except Exception as error:
        return jsonify({"error": str(error)}), 400


# [Insecure deserialization] unsafe YAML loader
@app.route("/api/config", methods=["POST"])
def load_config():
    try:
        parsed = yaml.load(request.get_data(as_text=True), Loader=yaml.Loader)
        return jsonify({"parsed": str(parsed)})
    except Exception as error:
        return jsonify({"error": str(error)}), 400


# [Insecure deserialization] pickle from untrusted input
@app.route("/api/session", methods=["POST"])
def restore_session():
    blob = (request.get_json(silent=True) or {}).get("blob", "")
    try:
        return jsonify({"session": str(pickle.loads(base64.b64decode(blob)))})
    except Exception as error:
        return jsonify({"error": str(error)}), 400


# [SSRF + disabled TLS verification]
@app.route("/api/fetch")
def fetch():
    url = request.args.get("url", "")
    try:
        response = requests.get(url, timeout=5, verify=False)
        return jsonify({"status": response.status_code, "body": response.text[:500]})
    except requests.RequestException as error:
        return jsonify({"error": str(error)}), 502


# [Open redirect]
@app.route("/api/redirect")
def open_redirect():
    return redirect(request.args.get("next", "/"))


# [Weak randomness] predictable reset token
@app.route("/api/reset-token")
def reset_token():
    return jsonify({"token": str(random.randint(100000, 999999))})


if __name__ == "__main__":
    # [Debug mode] Werkzeug debugger enabled. Bound to localhost on purpose.
    app.run(host="127.0.0.1", port=5001, debug=True)
