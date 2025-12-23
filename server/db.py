import sqlite3
import config
import json
import os

from passwords import make_password


def get_db():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY NOT NULL,
            hash_mode TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT,
            totp_secret TEXT,
            time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def users_json():
    json_path = os.path.join(os.path.dirname(__file__), "users.json")
    if not os.path.exists(json_path):
        return
    with open(json_path, "r", encoding="utf-8") as f:
        users = json.load(f)
    conn = get_db()

    for user in users:
        username = user.get("username")
        password = user.get("password")
        totp_secret = user.get("totp_secret")

        if not username or not password:
            continue

        row  = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if row :
            continue

        password_hash,salt, hash_mode = make_password(password)
        conn.execute("""INSERT INTO users (username, hash_mode, password_hash, salt, totp_secret) VALUES (?,?,?,?,?)""", (username, hash_mode, password_hash, salt, totp_secret))
        conn.commit()
        conn.close()
