import requests
import json
import pyotp
import secrets
import random
import os

BASE_URL = "http://127.0.0.1:5000"
JSON_FILE = "users.json"
WORDLIST_FILE = "test_wordlist.txt"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROCKYOU_FILE = os.path.join(BASE_DIR, "rockyou.txt")


def setup_experiment():
    print("--- Starting Setup ---")
    users_data = []

    # 1. הגדרת סיסמאות לרישום
    weak_pwds = ["123456", "password", "12345678", "qwerty", "12345", "111111", "123123", "sunshine", "iloveyou", "admin"]
    medium_pwds = ["Jonathan2020", "MyDogRex!", "Israel2026", "Pizza123!", "Summer2025", "CoffeeTime", "Liverpool#1", "FamilyFirst", "BlueSky2024", "User-527740437"]
    strong_pwds = ["Str0ngP@ss1!", "V3ryS3cur3#", "Admin$$2026", "Complex!2026", "SafetyFirst!", "Secure#123", "P@ssw0rd99", "Login2026!", "ProtectMe!", "FinalTest#1"]

    categories = [("Weak", weak_pwds), ("Medium", medium_pwds), ("Strong", strong_pwds)]

    # רישום משתמשים לשרת
    for cat_name, pwds in categories:
        for i, pwd in enumerate(pwds[:10]):
            username = f"{cat_name.lower()}_user_{i}"
            user_info = {
                "username": username,
                "password": pwd,
                "category": cat_name,
                "totp_secret": pyotp.random_base32()
            }
            payload = {"username": username, "password": pwd}

            try:
                r = requests.post(f"{BASE_URL}/register", json=payload, timeout=5)
                if r.status_code in [200, 201]:
                    print(f"[V] Registered: {username}")
                else:
                    continue
            except Exception as e:
                print(f"[!] Connection Error: {e}")
                continue

            users_data.append(user_info)

    # שמירת קובץ JSON לתוקף
    with open(JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(users_data, f, indent=4)

    # --- יצירת ה-Wordlist המחקרי ---
    print(f"\n[*] Generating research wordlist...")

    chosen_correct = random.sample(weak_pwds, 7) + random.sample(medium_pwds, 3)
    random.shuffle(chosen_correct) # ערבוב כדי שלא יהיו מסודרות לפי קושי

    # ב. קריאת סיסמאות מהמילון של RockYou
    if not os.path.exists(ROCKYOU_FILE):
        print(f"[!] {ROCKYOU_FILE} not found! Using fillers.")
        random_dictionary = [f"filler_{secrets.token_hex(4)}" for _ in range(7000)]
    else:
        with open(ROCKYOU_FILE, "r", encoding="latin-1") as rf:
            full_dict = [line.strip() for line in rf if line.strip()]
            random_dictionary = random.sample(full_dict, min(7000, len(full_dict)))

    # ג. כתיבת הקובץ הסופי
    with open(WORDLIST_FILE, "w", encoding="utf-8") as f:
        # 1. חמש סיסמאות לא נכונות בהתחלה (לבדיקת Lockout)
        for i in range(5):
            f.write(f"wrong_init_test_{i}\n")

        # 2. הסיסמאות הנכונות שנבחרו (7 קלות, 3 בינוניות)
        for pwd in chosen_correct:
            f.write(f"{pwd}\n")

        # 3. 7000 סיסמאות רנדומליות מהמילון
        for pwd in random_dictionary:
            f.write(f"{pwd}\n")

    print(f"--- Setup Finished ---")
    print(f"Wordlist saved to {WORDLIST_FILE}")
    print(f"Structure: 5 wrong | 10 selected correct (7 weak, 3 med) | {len(random_dictionary)} from dictionary")


if __name__ == "__main__":
    setup_experiment()