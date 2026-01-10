import json
import csv
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
RESULTS_DIR = os.path.join(BASE_DIR, "results")


def process_single_log(log_filename):
    log_path = os.path.join(LOGS_DIR, log_filename)
    csv_filename = f"res_{log_filename.replace('.log', '.csv')}"
    csv_path = os.path.join(RESULTS_DIR, csv_filename)

    summary_data = {}
    print(f"[*] Processing: {log_filename}")

    with open(log_path, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
                user = entry.get("username")
                attack = entry.get("attack_type")
                result = entry.get("result")
                latency = float(entry.get("latency_ms", 0))
                # שליפת הטיים-סטמפ המקורי מהלוג
                original_ts = entry.get("timestamp", "N/A")

                if not user or attack == "unknown":
                    continue

                key = (user, attack)

                if key not in summary_data:
                    prots = entry.get("protection_flags", {})
                    active_prots = [p for p, active in prots.items() if active]

                    summary_data[key] = {
                        "timestamp": original_ts,  # כאן נשמר הזמן המקורי מהלוג
                        "username": user,
                        "hash_mode": entry.get("hash_mode", "N/A"),
                        "protections": ", ".join(active_prots) if active_prots else "None",
                        "attack_type": attack,
                        "total_latency": 0.0,
                        "full_success": "No",
                        "is_totp": prots.get("totp", False)
                    }

                summary_data[key]["total_latency"] += latency

                if result == "login_success" and not summary_data[key]["is_totp"]:
                    summary_data[key]["full_success"] = "Yes"
                elif result == "totp_success":
                    summary_data[key]["full_success"] = "Yes"

            except:
                continue

    headers = ["Original Timestamp", "Username", "Hash Mode", "Protections", "Attack Type", "Total Execution Time (ms)",
               "Full Breach Success"]

    with open(csv_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for data in summary_data.values():
            writer.writerow([
                data["timestamp"], data["username"], data["hash_mode"], data["protections"],
                data["attack_type"], round(data["total_latency"], 2), data["full_success"]
            ])


def run():
    if not os.path.exists(RESULTS_DIR): os.makedirs(RESULTS_DIR)
    for f in os.listdir(LOGS_DIR):
        if f.endswith('.log'): process_single_log(f)
    print("Done! CSV files updated with original timestamps.")


if __name__ == "__main__":
    run()