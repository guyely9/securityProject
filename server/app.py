from flask import Flask, request, jsonify
import sqlite3
import secrets
import pyotp
from db import init_db, users_json, get_db, auto_reset_db
from passwords import make_password , check_password
import config
from logger import log_event, Timer
import time
from collections import  defaultdict, deque
import logging

app = Flask(__name__)
rate_buckets = {} #for rate limiting, token bucket
rate_locked = set() #for username that locked due to rate
fail_logins = defaultdict(int)#count the fail login/totp per user
lock_time = defaultdict(int)#time until unlock per user
captcha_fails = defaultdict(int)#count of failure in captcha per user
captcha_required = defaultdict(bool)#for indicating if captcha is needed per user
captcha_tokens = {}

#function to remove captcha tokens that expired from memory of tokens
def delete_tokens():
    now = int(time.time())
    expired = []
    for token, data in captcha_tokens.items():
        if data['expires'] <= now:
            expired.append(token)
    for token in expired:
        captcha_tokens.pop(token,None)

#check and return if the user need to provide captcha token
def need_captcha(username):
    return captcha_fails[username] >= config.CAPTCHA_FAIL

#check and return if the user is lock currently
def is_locked(username):
    return time.time() < lock_time[username]

#the user failed to regist then add to the failures and lock if the fails are in LOCKED_TRY
def fail(username):
    fail_logins[username] += 1
    if fail_logins[username] >= config.LOCKOUT_TRY:
        lock_time[username] = int(time.time()) + config.LOCKOUT_TIME
        fail_logins[username] = 0

#the user connect well. reset the fail counter and the lock
def success(username):
    fail_logins[username] =0
    lock_time[username] =0


#check if the user get to the number of requests in time define in config
def check_rate(username):
    now = time.time()
    b= rate_buckets.get(username)
    if b is None:
        rate_buckets[username] = {"tokens": config.RATE_LIMIT_TRY -1.0,"last": now}
        return True
    elapsed = now - b["last"]
    b["tokens"] = min(config.RATE_LIMIT_TRY, b["tokens"]+elapsed*config.RATE_REFILL)
    b["last"] = now
    if b["tokens"] <1.0:
        return False
    b["tokens"] -= 1.0
    return True


#this is endpoint to resist some client/ user to the system
@app.post("/register")
def register():
    t = Timer()
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    attack_type = data.get("attack_type", "unknown")
    if not username or not password: #check for valid input
        log_event(username=username or "", hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
                  result="missing_something", latency_ms=t.ms(), attack_type=attack_type)
        return jsonify({"ok": False, "error":"username or password are missing"}), 400
    conn = get_db()
    exists = conn.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone()
    if exists is not None: #the username exists
        conn.close()
        log_event(username=username, hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
                  result="username_exists", latency_ms=t.ms(), attack_type=attack_type)
        return jsonify({"ok": False, "error":"username already exists"}), 409
    try:
        pw_hash, salt, mode = make_password(password)
    except Exception as e:
        conn.close()
        log_event(username=username, hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
                  result="failed_in_hashing", latency_ms=t.ms(), attack_type=attack_type)
        return jsonify({"ok": False, "error": "hashing failed"}), 500

    conn.execute("INSERT INTO users (username, hash_mode, password_hash, salt, totp_secret) VALUES (?,?,?,?,?)", (username, mode, pw_hash, salt, None))
    conn.commit()
    conn.close()
    log_event(username=username, hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
              result="register_success", latency_ms=t.ms(), attack_type=attack_type)
    return jsonify({"ok": True, "endpoint": "register", "username": username}),201

#this endpoint for admin unlock, possible to remove user from lock
@app.post("/admin/unlock")
def admin_unlock():
    data = request.get_json(silent=True) or {}
    admin_key = data.get("admin_key", "")
    username = data.get("username", "")
    if admin_key != config.ADMIN_KEY:
        return jsonify({"ok": False, "error": "invalid admin_key"}), 403
    rate_locked.discard(username)
    rate_buckets.pop(username, None)
    return jsonify({"ok": True, "username": username}), 200

#this function return token captcha for login
@app.get("/admin/get_captcha")
def get_captcha():
    group_seed = request.args.get("group_seed", "")
    if str(group_seed) != str(config.GROUP_SEED):
        return jsonify({"ok": False, "error": "invalid group_seed"}), 403
    delete_tokens()
    token = secrets.token_urlsafe(16)
    captcha_tokens[token] = {
        "expires": int(time.time()) + config.CAPTCHA_TIME
    }
    return jsonify({"ok": True, "token": token}), 200

#this is endpoint for login with password to the system
@app.post("/login")
def login():
    t=Timer()
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    attack_type = data.get("attack_type", "manual_login")
    if config.PROTECTION_FLAGS["captcha"] and captcha_required[username]:#check if need captcha, token must be supplied and valid
        token = data.get("token", "")
        delete_tokens()
        if not token or token not in captcha_tokens or captcha_tokens[token]["expires"] <= int(time.time()): #check for valid token
            log_event(username=username or "", hash_mode=None, protection_flags=config.PROTECTION_FLAGS, result = "captcha_required", latency_ms=t.ms(), attack_type=attack_type)
            return jsonify({"ok": False, "captcha_required": True}), 403
        captcha_tokens.pop(token, None)#remove token from bucket
        log_event(username=username, hash_mode=None, protection_flags=config.PROTECTION_FLAGS, result= "captcha_token_used", latency_ms=t.ms(), attack_type=attack_type)
    if config.PROTECTION_FLAGS["lockout"]:#check lockout
        if is_locked(username):
            log_event(username=username or "", hash_mode=None, protection_flags=config.PROTECTION_FLAGS,result = "lockout is on", latency_ms=t.ms(), attack_type=attack_type)
            return jsonify({"ok": False, "error":"account is locked now"}), 423
    if config.PROTECTION_FLAGS["rate_limit"]:#check rate limiting
        if username in rate_locked:
            log_event(username=username,hash_mode = None, protection_flags= config.PROTECTION_FLAGS ,result="rate_limiting", latency_ms=t.ms(), attack_type=attack_type)
            return jsonify({"ok": False, "error": "too many attempts"}), 423
        if not check_rate(username):
            if config.RATE_HARD_LOCK:
                rate_locked.add(username)
            log_event(username= username or "", hash_mode=None, protection_flags=config.PROTECTION_FLAGS,result= "rate_limiting", latency_ms=t.ms(), attack_type=attack_type)
            return jsonify({"ok": False, "error": "too many attempts"}), 429
    if not username or not password:#validation check
        log_event(username = username or "", hash_mode=None,protection_flags= config.PROTECTION_FLAGS,
                  result= "missing_something", latency_ms=t.ms(), attack_type=attack_type)
        return jsonify({"ok": False, "error":"username or password are missing"}), 400
    conn = get_db()
    user = conn.execute("SELECT password_hash, salt, hash_mode, totp_secret FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if user is None:
        log_event(username=username, hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
                  result="user_not_found", latency_ms=t.ms(), attack_type=attack_type)
        return jsonify({"ok": False, "error":"username does not exist"}), 404
    #password verification
    hash = user["password_hash"]
    salt = user["salt"]
    hash_mode = user["hash_mode"]
    if not check_password(password, hash, salt, hash_mode):
        if config.PROTECTION_FLAGS["lockout"]:
            fail(username)
        captcha_fails[username] +=1
        if captcha_fails[username] >= config.CAPTCHA_FAIL:
            captcha_required[username] = True
        log_event(username=username, hash_mode=hash_mode, protection_flags=config.PROTECTION_FLAGS,
                  result="wrong_password", latency_ms=t.ms(),  attack_type = attack_type)
        return jsonify({"ok": False, "error":"wrong password"}), 401
    captcha_fails[username] = 0 #password is ok
    #captcha_required[username] = False
    totp_secret = user["totp_secret"]
    if totp_secret: #need to continue login with totp
        log_event(username=username, hash_mode=hash_mode, protection_flags=config.PROTECTION_FLAGS,
                  result="need_totp", latency_ms=t.ms(), attack_type=attack_type)
        return jsonify({"ok": True, "endpoint": "login", "username": username,"need_totp" : True}),200
    if config.PROTECTION_FLAGS["lockout"]:
        success(username)
    log_event(username=username, hash_mode=hash_mode, protection_flags=config.PROTECTION_FLAGS,
              result="login_success", latency_ms=t.ms(), attack_type=attack_type)
    captcha_required[username] = False
    captcha_fails[username] = 0
    return jsonify({"ok": True, "endpoint": "login", "username": username,"need_totp": False}),200

#this endpoint for login with totp, made the check for captcha, lockout,rate.
@app.post("/login_totp")
def login_totp():
    t = Timer()
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    code = str(data.get("code", "")).strip()
    attack_type = data.get("attack_type", "manual_totp")
    if config.PROTECTION_FLAGS["captcha"] and captcha_required[username]:#captcha check
        token = data.get("token", "")
        delete_tokens()
        if not token or token not in captcha_tokens or captcha_tokens[token]["expires"] <= int(time.time()):
            log_event(username=username or "", hash_mode=None, protection_flags=config.PROTECTION_FLAGS, result = "captcha_required", latency_ms=t.ms(), attack_type=attack_type)
            return jsonify({"ok": False, "captcha_required": True}), 403
        captcha_tokens.pop(token, None)
        captcha_required[username] = False
        captcha_fails[username] = 0
    if config.PROTECTION_FLAGS["lockout"]:# lockout check
        if is_locked(username):
            log_event(username=username or "", hash_mode=None, protection_flags=config.PROTECTION_FLAGS,result = "lockout is on", latency_ms=t.ms(), attack_type=attack_type)
            return jsonify({"ok": False, "error":"account is locking now"}), 423
    if config.PROTECTION_FLAGS["rate_limit"]:#rate limiting check
        if username in rate_locked:
            log_event(username=username or "", hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
                      result="rate_limiting", latency_ms=t.ms(), attack_type=attack_type)
            return jsonify({"ok": False, "error": "locked"}), 423
        if not check_rate(username):
            if config.RATE_HARD_LOCK:
                rate_locked.add(username)
            log_event(username=username or "", hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
                      result="rate_limiting", latency_ms=t.ms(), attack_type=attack_type)
            return jsonify({"ok": False, "error": "too many attempts"}), 429
    if not username or not code:#input validation
        log_event(username=username or "", hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
                  result="missing_something", latency_ms=t.ms(), attack_type=attack_type)
        return jsonify({"ok": False, "error":"username or code are missing"}), 400
    conn = get_db()
    row = conn.execute("SELECT totp_secret FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()

    if row is None:
        log_event(username=username, hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
                  result="user_not_found", latency_ms=t.ms(), attack_type=attack_type)
        return jsonify({"ok": False, "error":"username does not exist"}), 404
    totp_secret = row["totp_secret"]
    if not totp_secret:
        log_event(username=username or "", hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
                  result="totp_not_needed", latency_ms=t.ms(), attack_type=attack_type)
        return jsonify({"ok": False, "error":"totp_secret does not needed"}), 400
    totp = pyotp.TOTP(totp_secret)#verify TOTP
    if not totp.verify(code,valid_window=1):
        if config.PROTECTION_FLAGS["lockout"]:
            fail(username)
        log_event(username=username, hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
                  result="wrong_totp", latency_ms=t.ms(), attack_type=attack_type)
        captcha_fails[username] += 1
        if captcha_fails[username] >= config.CAPTCHA_FAIL:
            captcha_required[username] = True
        return jsonify({"ok": False, "error":"wrong totp code"}), 401
    if config.PROTECTION_FLAGS["lockout"]:
        success(username)
    log_event(username=username or "", hash_mode=None, protection_flags=config.PROTECTION_FLAGS,
              result="totp_success", latency_ms=t.ms(), attack_type=attack_type)
    captcha_fails[username] = 0
    return jsonify({"ok": True, "endpoint": "login_totp", "username": username}),200


if __name__ == "__main__":
    auto_reset_db()
    init_db()
 #   users_json()
 #   app.run(debug=True)
app.run(debug=True, threaded=True)