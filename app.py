# Simple intentionally vulnerable app: a scan target for the shift-left pipeline.
# Each weakness is one self-contained line so an AI patch can replace it cleanly.
# Do not deploy. The key below is a fake placeholder.
import hashlib
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)

API_KEY = "AKIAIOSFODNN7EXAMPLE"

db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE users (name TEXT, pw_hash TEXT)")


def hash_password(value):
    return hashlib.md5(value.encode()).hexdigest()


db.execute("INSERT INTO users VALUES (?, ?)", ("admin", hash_password("admin123")))


@app.route("/")
def home():
    return (
        "<h1>Simple lab</h1>"
        "<p>Try /hello?name=Ana, /login?name=admin&pw=admin123, "
        "/ping?host=127.0.0.1, /calc?expr=2%2B2</p>"
    )


@app.route("/hello")
def hello():
    return f"<h1>Hello {request.args.get('name', 'friend')}</h1>"


@app.route("/login")
def login():
    name = request.args.get("name", "")
    query = f"SELECT name FROM users WHERE name = '{name}' AND pw_hash = '{hash_password(request.args.get('pw', ''))}'"
    row = db.execute(query).fetchone()
    return {"ok": bool(row)}


@app.route("/ping")
def ping():
    result = subprocess.run("ping -c 1 " + request.args.get("host", "127.0.0.1"), shell=True, capture_output=True, text=True)
    return result.stdout


@app.route("/calc")
def calc():
    return str(eval(request.args.get("expr", "0")))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)
