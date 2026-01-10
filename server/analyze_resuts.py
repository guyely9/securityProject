import pandas as pd
import matplotlib.pyplot as plt
import os
import numpy as np

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, "results")


def analyze_research_data():
    summary_data = []

    if not os.path.exists(RESULTS_DIR):
        print("Error: Results directory not found!")
        return

    all_files = [f for f in os.listdir(RESULTS_DIR) if f.startswith('res_') and f.endswith('.csv')]

    for filename in all_files:
        path = os.path.join(RESULTS_DIR, filename)
        try:
            df = pd.read_csv(path)
            # ניקוי שם הקובץ לתצוגה בגרף
            name = filename.replace('res_', '').replace('logs_', '').replace('.csv', '').replace('_', ' ')

            for attack in ['password_spraying', 'brute_force']:
                sub_df = df[df['Attack Type'] == attack]
                if sub_df.empty: continue

                avg_time = sub_df['Total Execution Time (ms)'].mean()
                success_count = (sub_df['Full Breach Success'] == 'Yes').sum()
                success_rate = (success_count / len(sub_df)) * 100

                summary_data.append({
                    'Scenario': name,
                    'Attack': attack,
                    'AvgTime': avg_time,
                    'SuccessCount': success_count,
                    'SuccessRate': success_rate,
                    'IsDefense': any(d in name.lower() for d in ['lockout', 'captcha', 'rate', 'totp', 'pepper'])
                })
        except Exception as e:
            print(f"Error processing {filename}: {e}")

    df_final = pd.DataFrame(summary_data)
    if df_final.empty: return
    create_plots(df_final)


def create_plots(df):
    plt.style.use('ggplot')
    hashes = df[df['IsDefense'] == False]
    defenses = df[df['IsDefense'] == True]

    # גרף 1: זמן ממוצע - האשים (לכל התקיפות)
    plot_bar(hashes, 'AvgTime', 'Avg Total Execution Time (ms) - Pure Hashes', 'time_pure.png')

    # גרף 2: זמן ממוצע - הגנות (לכל התקיפות)
    plot_bar(defenses, 'AvgTime', 'Avg Total Execution Time (ms) - Defenses', 'time_defenses.png')

    # גרף 3: מספר פריצות מוצלח (מספרים אבסולוטיים)
    plot_bar(df, 'SuccessCount', 'Number of Successful Breaches (Absolute)', 'success_count_abs.png')

    # גרף 4: אחוז פריצות מוצלח
    plot_bar(df, 'SuccessRate', 'Breach Success Rate (%)', 'success_rate_percent.png')

    print(f"\n[V] Success! All 4 graphs saved in {RESULTS_DIR}")
    plt.show()


def plot_bar(data, y_field, title, filename):
    if data.empty: return
    scenarios = data['Scenario'].unique()
    x = np.arange(len(scenarios))
    width = 0.35

    fig, ax = plt.subplots(figsize=(12, 7))

    # שליפת נתונים לפי סוג התקפה
    spray = [data[(data['Scenario'] == s) & (data['Attack'] == 'password_spraying')][y_field].sum() for s in scenarios]
    brute = [data[(data['Scenario'] == s) & (data['Attack'] == 'brute_force')][y_field].sum() for s in scenarios]

    ax.bar(x - width / 2, spray, width, label='Password Spraying', color='#3498db')
    ax.bar(x + width / 2, brute, width, label='Brute Force', color='#e74c3c')

    ax.set_ylabel(y_field)
    ax.set_title(title)
    ax.set_xticks(x)
    ax.set_xticklabels(scenarios, rotation=30, ha='right')
    ax.legend()

    # הוספת טקסט מעל העמודות
    for i in range(len(x)):
        ax.text(x[i] - width / 2, spray[i], f'{spray[i]:.1f}', ha='center', va='bottom', fontsize=8)
        ax.text(x[i] + width / 2, brute[i], f'{brute[i]:.1f}', ha='center', va='bottom', fontsize=8)

    plt.tight_layout()
    plt.savefig(os.path.join(RESULTS_DIR, filename))


if __name__ == "__main__":
    analyze_research_data()