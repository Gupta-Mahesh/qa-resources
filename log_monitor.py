import re
import csv
import sys
from collections import defaultdict
from pathlib import Path
from tabulate import tabulate  # pip install tabulate
from datetime import datetime

# Extract data from one log file
def extract_all_process_entries(log_lines):
    pattern = (
        r'(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+'
        r'(\d+)\s+\d+\s+([IDEWV])\s+([\w\-.]+):'
    )
    entries = defaultdict(list)
    for line in log_lines:
        match = re.search(pattern, line)
        if match:
            timestamp = match.group(1)
            pid = match.group(2)
            level = match.group(3)
            process = match.group(4)
            entries[process].append((timestamp, pid, level))
    return entries

# Read ALL log files in a folder
def aggregate_logs_from_dir(folder_path):
    combined = defaultdict(list)
    for log_file in Path(folder_path).glob("*.log"):
        log_lines = log_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        file_entries = extract_all_process_entries(log_lines)
        for process, logs in file_entries.items():
            combined[process].extend(logs)
    return combined

# PID stability
def analyze_pid_stability(entries):
    pid_table = []
    for process, logs in entries.items():
        seen_pids = []
        pid_timeline = {}
        for timestamp, pid, _ in logs:
            if pid not in seen_pids:
                seen_pids.append(pid)
                pid_timeline[pid] = timestamp
        status = "Stable" if len(seen_pids) == 1 else "Changed"
        for pid in seen_pids:
            pid_table.append([process, pid, pid_timeline[pid], status])
    return pid_table

# Log levels
def analyze_log_levels(entries):
    level_table = []
    for process, logs in entries.items():
        level_count = {'I': 0, 'D': 0, 'E': 0, 'W': 0, 'V': 0}
        for _, _, level in logs:
            if level in level_count:
                level_count[level] += 1
        for level, count in level_count.items():
            if count > 0:
                level_table.append([process, level, count])
    return level_table


def get_timestamped_filename(base_name):
    # Format: pid_report_2025-08-16_0140.csv
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    return Path.cwd() / f"{base_name}_{timestamp}.csv"


# Save to CSV
def export_to_csv(pid_table, level_table):
    pid_csv_path = get_timestamped_filename("pid_report")
    level_csv_path = get_timestamped_filename("log_level_report")

    with open(pid_csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Process', 'PID', 'Start Time', 'PID Status'])
        writer.writerows(pid_table)

    with open(level_csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Process', 'Log Level', 'Count'])
        writer.writerows(level_table)

    print(f"PID CSV saved to: {pid_csv_path}")
    print(f"Log Level CSV saved to: {level_csv_path}")


def main():
    folder = sys.argv[1] #"D:/test/logs"  # Your log folder
    #pid_csv = "D:/test/pid_report1.csv"
    #level_csv = "D:/test/loglevel_report1.csv"

    entries = aggregate_logs_from_dir(folder)
    if not entries:
        print("No matching log entries found.")
        return

    pid_table = analyze_pid_stability(entries)
    level_table = analyze_log_levels(entries)

    print("\n=== PID Stability ===")
    print(tabulate(pid_table, headers=["Process", "PID", "Time Stamp", "PID Status"], tablefmt="pretty"))

    print("\n=== Log Level Summary ===")
    print(tabulate(level_table, headers=["Process", "Log Level", "Count"], tablefmt="pretty"))

    export_to_csv(pid_table, level_table)

if __name__ == "__main__":
    main()