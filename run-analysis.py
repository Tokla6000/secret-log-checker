import json
import os
import subprocess

# Run pyre analyze and capture output
result = subprocess.run(
    ["pyre", "analyze"],
    capture_output=True,
    text=True
)

data = json.loads(result.stdout)

# Collect reported files
reported_files = set()
for issue in data:
    path = issue["path"]
    if path.startswith("benchmarks/"):
        filename = os.path.basename(path)
        reported_files.add(filename)

# Collect all benchmark files
benchmark_files = []
for root, _, files in os.walk("benchmarks"):
    for file in files:
        if file.endswith(".py"):
            benchmark_files.append(file)

benchmark_files.sort()

def print_table(rows):
    headers = ["File", "Expected", "Reported", "Result"]

    # compute column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(val))

    def format_row(row):
        return " | ".join(val.ljust(col_widths[i]) for i, val in enumerate(row))

    separator = "-+-".join("-" * w for w in col_widths)

    print(format_row(headers))
    print(separator)
    for row in rows:
        print(format_row(row))
        
rows = []

for file in benchmark_files:
    expected = "Leak" if "unsafe" in file else "Safe"
    reported = "Yes" if file in reported_files else "No"

    if expected == "Leak" and reported == "Yes":
        result = "TP"
    elif expected == "Leak" and reported == "No":
        result = "FN"
    elif expected == "Safe" and reported == "Yes":
        result = "FP"
    else:
        result = "TN"

    rows.append([file, expected, reported, result])

print_table(rows)