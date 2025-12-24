from flask import Flask, request, jsonify
import sqlite3
import secrets
import pyotp
from db import init_db, get_db, users_json
from passwords import make_password , check_password
import config
from logger import log_event, Timer


app = Flask(__name__)


@app.post("/register")
def register():
    t = Timer()
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if not username or not password:
        log_event(username=username or "", hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
                  result="missing_something", latency_ms=t.ms())
        return jsonify({"ok": False, "error":"username or password are missing"}), 400
    conn = get_db()
    exists = conn.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone()
    if exists is not None:
        conn.close()
        log_event(username=username, hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
                  result="username_exists", latency_ms=t.ms())
        return jsonify({"ok": False, "error":"username already exists"}), 409
    try:
        pw_hash, salt, mode = make_password(password)
    except Exception as e:
        conn.close()
        log_event(username=username, hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
                  result="failed_in_hashing", latency_ms=t.ms())
        return jsonify({"ok": False, "error": "hashing failed"}), 500

    conn.execute("INSERT INTO users (username, hash_mode, password_hash, salt, totp_secret) VALUES (?,?,?,?,?)", (username, mode, pw_hash, salt, None))
    conn.commit()
    conn.close()
    log_event(username=username, hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
              result="register_success", latency_ms=t.ms())
    return jsonify({"ok": True, "endpoint": "register", "username": username}),201

@app.post("/login")
def login():
    t=Timer()
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if not username or not password:
        log_event(username = username or "", hash_mode=None,protection_flags= config.PROTECTION_FLAGS,
                  result= "missing_something", latency_ms=t.ms())
        return jsonify({"ok": False, "error":"username or password are missing"}), 400
    conn = get_db()
    user = conn.execute("SELECT password_hash, salt, hash_mode, totp_secret FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if user is None:
        log_event(username=username, hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
                  result="user_not_found", latency_ms=t.ms())
        return jsonify({"ok": False, "error":"username does not exist"}), 404
    hash = user["password_hash"]
    salt = user["salt"]
    hash_mode = user["hash_mode"]
    if not check_password(password, hash, salt, hash_mode):
        log_event(username=username, hash_mode=hash_mode, protection_flags=config.PROTECTION_FLAGS,
                  result="wrong_password", latency_ms=t.ms())
        return jsonify({"ok": False, "error":"wrong password"}), 401
    totp_secret = user["totp_secret"]
    if totp_secret:
        log_event(username=username, hash_mode=hash_mode, protection_flags=config.PROTECTION_FLAGS,
                  result="need_totp", latency_ms=t.ms())
        return jsonify({"ok": True, "endpoint": "login", "username": username,"need_totp" : True}),200
    log_event(username=username, hash_mode=hash_mode, protection_flags=config.PROTECTION_FLAGS,
              result="login_success", latency_ms=t.ms())
    return jsonify({"ok": True, "endpoint": "login", "username": username,"need_totp": False}),200

@app.post("/login_totp")
def login_totp():
    t = Timer()
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    code = str(data.get("code", "")).strip()
    if not username or not code:
        log_event(username=username or "", hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
                  result="missing_something", latency_ms=t.ms())
        return jsonify({"ok": False, "error":"username or code are missing"}), 400
    conn = get_db()
    row = conn.execute("SELECT totp_secret FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if row is None:
        log_event(username=username, hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
                  result="user_not_found", latency_ms=t.ms())
        return jsonify({"ok": False, "error":"username does not exist"}), 404
    totp_secret = row["totp_secret"]
    if not totp_secret:
        log_event(username=username or "", hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
                  result="totp_not_needed", latency_ms=t.ms())
        return jsonify({"ok": False, "error":"totp_secret does not needed"}), 400
    totp = pyotp.TOTP(totp_secret)
    if not totp.verify(code,valid_window=1):
        log_event(username=username, hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
                  result="wrong_totp", latency_ms=t.ms())
        return jsonify({"ok": False, "error":"wrong totp code"}), 401
    log_event(username=username or "", hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
              result="totp_success", latency_ms=t.ms())
    return jsonify({"ok": True, "endpoint": "login_totp", "username": username}),200


if __name__ == "__main__":
    init_db()
    users_json()
    app.run(debug=True)
