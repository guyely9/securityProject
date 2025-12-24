import requests
import json
import pyotp
from config import GROUP_SEED

BASE_URL = "http://127.0.0.1:5000"


def setup_and_save():
    users_data = []

    # הגדרת המשתמשים
    categories = {
        "weak": ["123456", "password", "12345", "qwerty", "12345678", "admin", "111111", "welcome", "123123",
                 str(GROUP_SEED)],
        "medium": [f"User!{i}*2025" for i in range(10)],
        "strong": [f"Strong#P@ssw0rd!{i * 13}#Secure" for i in range(10)]
    }

    print("--- Starting Setup and generating users.json ---")

    for cat, passwords in categories.items():
        for i, pwd in enumerate(passwords):
            username = f"{cat}_user_{i}"


            # יצירת סוד TOTP ייחודי לכל משתמש
            otp_secret = pyotp.random_base32()

            user_info = {
                "username": username,
                "password": pwd,
                "totp_secret": otp_secret
            }

            # ניסיון רישום בשרת
            try:
                response = requests.post(f"{BASE_URL}/register", json=user_info)
                if response.status_code == 201:
                    print(f"[+] Registered: {username}")
                elif response.status_code == 409:
                    print(f"[-] User already exists: {username}")
            except Exception as e:
                print(f"[!] Error registering {username}: {e}")

            # הוספה לרשימה שתישמר ב-JSON
            users_data.append(user_info)

    # שמירת הקובץ - מחוץ ללולאות
    with open("users.json", "w") as f:
        json.dump(users_data, f, indent=4)

    print("\n[V] SUCCESS: 'users.json' has been created with 30 users!")


if __name__ == "__main__":
    setup_and_save()