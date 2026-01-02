import requests
import json
import pyotp
import os
from config import GROUP_SEED

BASE_URL = "http://127.0.0.1:5000"
JSON_FILE = "users.json"


def setup_and_generate_json():
    users_data = []

    # הגדרת המשתמשים לפי קטגוריות חוזק
    categories = {
        "weak": ["123456", "password", "12345", "qwerty", str(GROUP_SEED), "admin", "111111", "123123", "welcome",
                 "login123"],
        "medium": [f"User!{i}*2025" for i in range(10)],
        "strong": [f"Strong#P@ssw0rd!{i}#Secure" for i in range(10)]
    }

    print("--- Starting Setup ---")

    for cat, passwords in categories.items():
        for i, pwd in enumerate(passwords):
            username = f"{cat}_user_{i}"
            otp_secret = pyotp.random_base32()  # יצירת סוד TOTP ייחודי

            user_info = {
                "username": username,
                "password": pwd,
                "totp_secret": otp_secret
            }

            # 1. ניסיון רישום בשרת (כדי שייכנס לדאטה-בייס)
            try:
                requests.post(f"{BASE_URL}/register", json=user_info)
                print(f"[+] Registered in Server: {username}")
            except Exception as e:
                print(f"[!] Server error for {username}: {e}")

            # 2. הוספה לרשימה שתישמר ב-JSON
            users_data.append(user_info)

    # יצירת הקובץ פיזית בתיקייה
    with open(JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(users_data, f, indent=4)

    print(f"\n[V] SUCCESS: '{JSON_FILE}' was created at: {os.path.abspath(JSON_FILE)}")


if __name__ == "__main__":
    setup_and_generate_json()