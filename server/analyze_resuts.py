import pandas as pd
import matplotlib.pyplot as plt
import os
import numpy as np

# הגדרות נתיבים וקבצים
RESULTS_DIR = 'results'
FILE_ORDER = [
    'res_01_pure_sha256.csv', 'res_02_pure_argon2.csv', 'res_03_pure_bcrypt.csv',
    'res_04_protect_pepper_only.csv', 'res_05_protect_totp_only.csv',
    'res_06_protect_rate_only.csv', 'res_07_protect_lockout_only.csv',
    'res_08_protect_captcha_only.csv', 'res_09_var_hashing_plus_active.csv',
    'res_10_full_defense_all_on.csv'
]


def run_full_analysis():
    data_list = []

    # הדפסת כותרת לניתוח הסטטיסטי בטרמינל
    print("\n" + "=" * 85)
    print(f"{'Scenario Name':<35} | {'Mean':<7} | {'Median':<7} | {'P90':<7} | {'Success%'}")
    print("-" * 85)

    for filename in FILE_ORDER:
        path = os.path.join(RESULTS_DIR, filename)
        if not os.path.exists(path):
            continue

        df = pd.read_csv(path)

        # עיבוד שם התרחיש
        display_name = filename.replace('res_', '').replace('.csv', '').replace('_', ' ')

        # חישוב מדדי זמן (Latency)
        latencies = df['latency_ms']
        avg = latencies.mean()
        med = latencies.median()
        p90 = np.percentile(latencies, 90)

        # חישוב אחוזי הצלחה
        success_rate = (len(df[df['result'] == 'success']) / len(df)) * 100

        # שמירה לרשימה עבור הגרפים
        data_list.append({
            'name': display_name,
            'mean': avg,
            'median': med,
            'p90': p90,
            'success': success_rate,
            'is_pure': 'pure' in filename
        })

        # הדפסת שורה לטבלה בטרמינל
        print(f"{display_name:<35} | {avg:7.1f} | {med:7.1f} | {p90:7.1f} | {success_rate:6.1f}%")

    print("=" * 85)

    # יצירת הגרפים
    generate_plots(pd.DataFrame(data_list))


def generate_plots(df):
    plt.style.use('ggplot')

    # --- גרף 1: מהירות האלגוריתמים ללא הגנה (Baseline) ---
    plt.figure(figsize=(10, 6))
    pure_df = df[df['is_pure']]
    plt.bar(pure_df['name'], pure_df['mean'], color=['#3498db', '#e74c3c', '#2ecc71'])
    plt.title('Graph 1: Average Latency - Pure Hashing Algorithms')
    plt.ylabel('Latency (ms)')
    plt.xticks(rotation=15)
    plt.savefig(os.path.join(RESULTS_DIR, '01_pure_latency.png'))

    # --- גרף 2: מהירות כל ההרצות (כולל הגנות) ---
    plt.figure(figsize=(12, 8))
    plt.barh(df['name'], df['mean'], color='teal')
    plt.title('Graph 2: Comparison of Latency Across All Scenarios')
    plt.xlabel('Average Latency (ms)')
    plt.tight_layout()
    plt.savefig(os.path.join(RESULTS_DIR, '02_all_scenarios_latency.png'))

    # --- גרף 3: אחוזי הצלחה ללא הגנות ---
    plt.figure(figsize=(10, 6))
    plt.bar(pure_df['name'], pure_df['success'], color='#f39c12')
    plt.title('Graph 3: Attacker Success Rate (Pure Hashing Only)')
    plt.ylabel('Success Rate (%)')
    plt.ylim(0, 110)
    for i, val in enumerate(pure_df['success']):
        plt.text(i, val + 2, f"{val:.1f}%", ha='center', fontweight='bold')
    plt.savefig(os.path.join(RESULTS_DIR, '03_pure_success_rate.png'))

    print("\n[V] שלושת הגרפים נשמרו בתיקיית results.")
    plt.show()


if __name__ == "__main__":
    run_full_analysis()