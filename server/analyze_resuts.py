import csv
import statistics
import matplotlib.pyplot as plt
import os


def generate_research_summary():
    print("\n" + "=" * 40)
    print("--- GLOBAL RESEARCH ANALYSIS ---")
    print("=" * 40)

    results_folder = "results"
    data_by_mode = {}

    # סריקת כל קבצי ה-CSV בתיקיית התוצאות
    for filename in os.listdir(results_folder):
        if filename.endswith(".csv"):
            path = os.path.join(results_folder, filename)
            with open(path, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # שימי לב: השתמשי בשמות העמודות המדויקים שיש ב-CSV שלך
                    # אם ב-CSV העמודה נקראת 'response_time', שנו את 'latency_ms' ל-'response_time'
                    mode = row.get('hash_mode', filename.replace('res_', '').replace('.csv', ''))
                    latency = float(row.get('latency_ms') or row.get('response_time', 0))

                    if mode not in data_by_mode:
                        data_by_mode[mode] = []
                    data_by_mode[mode].append(latency)

    if not data_by_mode:
        print("No data found in results folder.")
        return

    modes, avg_latencies = [], []

    for mode, latencies in data_by_mode.items():
        avg = statistics.mean(latencies)
        modes.append(mode)
        avg_latencies.append(avg)

        print(f"\nAnalysis for Mode: {mode}")
        print(f"Average Latency: {avg:.4f} s")
        # חישוב כמה ניסיונות תקיפה אפשר להריץ בשנייה
        print(f"Approx. Attempts per Second: {1 / avg if avg > 0 else 'Inf':.2f}")

    create_comparison_graph(modes, avg_latencies)


def create_comparison_graph(modes, latencies):
    plt.figure(figsize=(10, 6))
    plt.bar(modes, latencies, color=['skyblue', 'salmon', 'lightgreen'])
    plt.xlabel('Algorithm')
    plt.ylabel('Average Time (seconds)')
    plt.title('Security impact: Time Cost per Password Guess')
    plt.savefig('results/latency_comparison.png')
    print("\n[V] Success: Comparison graph saved in 'results/latency_comparison.png'")
    plt.show()


if __name__ == "__main__":
    generate_research_summary()