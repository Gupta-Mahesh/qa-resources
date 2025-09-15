import re
import csv
import os
import sys
import glob
from datetime import datetime
from tabulate import tabulate # type: ignore
from collections import defaultdict

# Check for folder path argument
if len(sys.argv) != 2:
    print("Usage: python analyze_logs.py <log_folder_path>")
    sys.exit(1)

log_folder = sys.argv[1]
current_datetime = datetime.now()
csv_output_path = "zwave_bulk_analysis_"+ str(current_datetime.strftime("%Y-%m-%d_%H%M%S"))+".csv"

# Find all .log files in the folder
log_files = glob.glob(os.path.join(log_folder, "*.log"))

if not log_files:
    print(f"No .log files found in folder: {log_folder}")
    sys.exit(1)

# Regex patterns
request_pattern = re.compile(
    r"(?P<timestamp>\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}).*Calling sendZWaveCommand.*Node ID = (?P<node_id>\d+).*Token = (?P<token>0x[0-9a-fA-F]+)",
    re.IGNORECASE
)

response_pattern = re.compile(
    r"zwaveCommandResult\(\).*?Node ID = (?P<node_id>\d+), Cmd Status = (?P<status>0x[0-9a-fA-F]+), Token = (?P<token>0x[0-9a-fA-F]+)",
    re.IGNORECASE
)

# Use defaultdicts for fast lookup
requests = defaultdict(dict)
responses = defaultdict(dict)

# Process each log file
for file_path in log_files:
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue

                if "sendZWaveCommand" in line:
                    req_match = request_pattern.search(line)
                    if req_match:
                        token = req_match.group("token").lower().strip()
                        requests[token] = {
                            "timestamp": req_match.group("timestamp"),
                            "node_id": req_match.group("node_id"),
                            "source_file": os.path.basename(file_path)
                        }

                elif "zwaveCommandResult()" in line:
                    
                    res_match = response_pattern.search(line)
                    if res_match:
                        token = res_match.group("token").lower().strip()
                        responses[token] = {
                            "node_id": res_match.group("node_id"),
                            "status": res_match.group("status")
                        }
    except Exception as e:
        print(f" Error reading {file_path}: {e}")

# Prepare final data
final_data = []
for token, req in requests.items():
    if token in responses:
        result = "Pass"
        status = responses[token]["status"]
    else:
        result = "Fail"
        status = "N/A"

    final_data.append([
        req["timestamp"],
        req["node_id"],
        token,
        status,
        result,
        req["source_file"]
    ])

# Print tabular output
headers = ["Timestamp", "Node ID", "Token ID", "Cmd Status", "Result", "Source File"]
print("\n Combined Request–Response Summary:\n")
print(tabulate(final_data, headers=headers, tablefmt="grid"))

# export to CSV
try:
    with open(csv_output_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)
        for row in final_data:
            row[0] = " "+row[0]
            writer.writerow(row)
            #writer.writerows(final_data)
    print(f"\n Data saved to CSV: {csv_output_path}")
except Exception as e:
    print(f" Failed to write CSV: {e}")