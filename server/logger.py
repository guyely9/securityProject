import json
import os
import time
from datetime import datetime, timezone
import config


class Timer:
    def __init__(self):
        self.start = time.perf_counter()

    def ms(self):
        return int((time.perf_counter() - self.start) * 1000)


def log_event(username, result, hash_mode=None, attack_type="unknown", protection_flags=None, latency_ms=None):
    try:
        # מוצא את הנתיב של תיקיית ה-server (איפה שנמצא logger.py)
        server_dir = os.path.dirname(os.path.abspath(__file__))

        # מכוון לתיקיית logs שכבר קיימת בתוך server
        logs_dir = os.path.join(server_dir, "logs")

        # ודוא שהתיקייה קיימת (למקרה שהיא נמחקה בטעות)
        if not os.path.exists(logs_dir):
            os.makedirs(logs_dir)

        current_mode = getattr(config, "HASH_MODE", "general")
        # 2. זיהוי ההגנות הפעילות מתוך ה-config
        active_protections = [name for name, active in config.PROTECTION_FLAGS.items() if active]
        # 3. יצירת סיומת לשם הקובץ
        if active_protections:
        # מחבר את שמות ההגנות עם קו תחתון, למשל: lockout_captcha
            prot_suffix = "_" + "_".join(active_protections)
        else:
        # אם אין הגנות פעילות
            prot_suffix = "_no_protection"

        # 4. בניית שם הקובץ הסופי
        log_filename = f"logs_{current_mode}{prot_suffix}.log"
        log_path = os.path.join(logs_dir, log_filename)

        row = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "group_seed": getattr(config, "GROUP_SEED", "N/A"),
            "username": username,
            "hash_mode": hash_mode or current_mode,
            "attack_type": attack_type,
            "protection_flags": protection_flags or {},
            "result": result,
            "latency_ms": latency_ms
        }

        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    except Exception as e:
        print(f"!!! LOGGER ERROR: {e}")