import csv
import statistics
import matplotlib.pyplot as plt

LOG_FILE = "attack_research_results.csv"


# הפוקנציה שמפיקה את הסיכום הסטטיסטי
def generate_research_summary():
    print("\n" + "=" * 40)
    print("--- GLOBAL RESEARCH ANALYSIS ---")
    print("=" * 40)

    data_by_mode = {}

    try:
        with open(LOG_FILE, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                mode = row['hash_mode']
                if mode not in data_by_mode:
                    data_by_mode[mode] = []
                data_by_mode[mode].append(float(row['latency_ms']))

        if not data_by_mode:
            print("No data found in CSV.")
            return

        modes = []
        avg_latencies = []

        for mode, latencies in data_by_mode.items():
            avg = statistics.mean(latencies)
            modes.append(mode)
            avg_latencies.append(avg)

            print(f"\nAnalysis for Mode: {mode}")
            print(f"Total Attempts Recorded: {len(latencies)}")
            print(f"Average Latency: {avg:.2f} ms")
            print(f"Median Latency: {statistics.median(latencies):.2f} ms")
            print(f"Approx. Attempts per Second: {1000 / avg:.2f}")

        # יצירת גרף השוואתי אוטומטי לדוח
        create_comparison_graph(modes, avg_latencies)
        print("\n" + "=" * 40)

    except FileNotFoundError:
        print("Log file not found. Run attacker.py first.")


def create_comparison_graph(modes, latencies):
    plt.figure(figsize=(10, 6))
    plt.bar(modes, latencies, color=['blue', 'green', 'red', 'orange'])
    plt.xlabel('Hashing Mode')
    plt.ylabel('Average Latency (ms)')
    plt.title('Security impact: Latency per Hashing Algorithm')
    plt.savefig('latency_comparison.png')  # שומר את הגרף כתמונה
    print("\n[V] Success: Comparison graph saved as 'latency_comparison.png'")


if __name__ == "__main__":
    generate_research_summary()