import json
import time
from datetime import datetime, timezone
from unittest import result

import config


def current_time():
    return datetime.now(timezone.utc).isoformat()

def log_event(username, result, hash_mode= None, protection_flags = None, latency_ms= None):
    row = {
        "timestamp": current_time(),
        "group_seed": getattr(config, "GROUP_SEED", None),
        "username": username,
        "hash_mode": hash_mode,
        "protection_flags": protection_flags or {},
        "result": result ,
        "latency_ms": latency_ms,
    }

    with open("attempts.log", "a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii = False) + "\n")

class Timer:
    def __init__(self):
        self.start = time.perf_counter()

    def ms(self):
        return int((time.perf_counter() - self.start)*1000)