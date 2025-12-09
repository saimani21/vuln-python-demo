import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# ❌ Command injection example
@app.route("/run")
def run_cmd():
    cmd = request.args.get("cmd", "echo hello")
    os.system(cmd)  # insecure
    return "OK"

# ❌ SQL injection example
@app.route("/user")
def get_user():
    username = request.args.get("name", "admin")
    conn = sqlite3.connect("test.db")
    cur = conn.cursor()
    query = f"SELECT * FROM users WHERE name = '{username}'"  # insecure
    cur.execute(query)
    return str(cur.fetchall())
