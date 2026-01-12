import pandas as pd
import matplotlib.pyplot as plt
import os
import numpy as np
import warnings

# השתקת אזהרות המערכת כדי לקבל פלט נקי
warnings.filterwarnings('ignore')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, "results")


def get_user_strength(username):
    u = str(username).lower()
    if 'weak' in u: return 'Weak'
    if 'medium' in u: return 'Medium'
    return 'Strong'


def analyze_research_data():
    summary_data = []

    if not os.path.exists(RESULTS_DIR):
        print("Error: Results directory not found!")
        return

    all_files = [f for f in os.listdir(RESULTS_DIR) if f.startswith('res_') and f.endswith('.csv')]

    # כותרת הטבלה להעתקה
    header = f"{'Scenario':<35} | {'Attack':<18} | {'Avg (ms)':<10} | {'Median':<10} | {'P90':<10} | {'Success'}"
    print("\n" + "=" * 110)
    print(header)
    print("-" * 110)

    for filename in all_files:
        path = os.path.join(RESULTS_DIR, filename)
        try:
            df = pd.read_csv(path)
            name = filename.replace('res_', '').replace('logs_', '').replace('.csv', '').replace('_', ' ')

            for attack in ['password_spraying', 'brute_force']:
                sub_df = df[df['Attack Type'] == attack].copy()  # שימוש ב-copy מונע אזהרות
                if sub_df.empty: continue

                # חישוב מדדים
                times = sub_df['Total Execution Time (ms)']
                avg_time = times.mean()
                median_time = times.median()
                p90_time = times.quantile(0.9)

                # ניתוח הצלחות לפי חוזק
                sub_df.loc[:, 'Strength'] = sub_df['Username'].apply(get_user_strength)
                successes = sub_df[sub_df['Full Breach Success'] == 'Yes']

                weak_s = (successes['Strength'] == 'Weak').sum()
                med_s = (successes['Strength'] == 'Medium').sum()
                total_s = len(successes)

                # הדפסת שורה נקייה לטרמינל
                success_str = f"{total_s} (W:{weak_s}, M:{med_s})"
                print(
                    f"{name[:35]:<35} | {attack:<18} | {avg_time:<10.1f} | {median_time:<10.1f} | {p90_time:<10.1f} | {success_str}")

                summary_data.append({
                    'Scenario': name, 'Attack': attack, 'AvgTime': avg_time,
                    'WeakSuccess': weak_s, 'MediumSuccess': med_s,
                    'IsDefense': any(d in name.lower() for d in ['lockout', 'captcha', 'rate', 'totp', 'pepper'])
                })
        except Exception as e:
            pass  # התעלמות משגיאות קטנות בקבצים לא תקינים

    print("=" * 110 + "\n")

    df_final = pd.DataFrame(summary_data)
    if not df_final.empty:
        create_stacked_plot(df_final)


def create_stacked_plot(df):
    pass


if __name__ == "__main__":
    analyze_research_data()