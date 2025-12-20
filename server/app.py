from flask import Flask, request, jsonify
import sqlite3
import secrets
from db import init_db, get_db
from passwords import make_password
from config import HASH_MODE

app = Flask(__name__)


@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"ok": False, "error":"username or password are missing"}), 400
    conn = get_db()
    exists = conn.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone()
    if exists is not None:
        conn.close()
        return jsonify({"ok": False, "error":"username already exists"}), 409
    try:
        pw_hash, salt, mode = make_password(password)
    except Exception as e:
        conn.close()
        return jsonify({"ok": False, "error": "hashing failed"}), 500

    conn.execute("INSERT INTO users (username, hash_mode, password_hash, salt, totp_secret) VALUES (?,?,?,?,?)", (username, mode, pw_hash, salt, None))
    conn.commit()
    conn.close()
    return jsonify({"ok": True, "endpoint": "register", "username": username}),201



if __name__ == "__main__":
    init_db()
    app.run(debug=True)
