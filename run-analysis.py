import json
import os
import subprocess

result = subprocess.run(
    ["pyre", "analyze"],
    capture_output=True,
    text=True
)

output = result.stdout + "\n" + result.stderr

start = output.find("[\n")
if start == -1:
    print("No JSON found")
    print(output)
    exit(1)

# find the FIRST complete JSON array (matching brackets)
depth = 0
end = None

for i in range(start, len(output)):
    if output[i] == "[":
        depth += 1
    elif output[i] == "]":
        depth -= 1
        if depth == 0:
            end = i
            break

if end is None:
    print("Could not find end of JSON")
    exit(1)

json_str = output[start:end + 1]
data = json.loads(json_str)

reported_files = set()

for issue in data:
    path = issue["path"]
    if path.startswith("benchmarks/"):
        reported_files.add(os.path.basename(path))

benchmark_files = []

for root, _, files in os.walk("benchmarks"):
    for file in files:
        if file.endswith(".py") and file != "__init__.py":
            benchmark_files.append(file)

benchmark_files.sort()

rows = []

for file in benchmark_files:
    expected = "Leak" if "unsafe" in file else "Safe"
    reported = "Yes" if file in reported_files else "No"

    if expected == "Leak" and reported == "Yes":
        result_label = "TP"
    elif expected == "Leak" and reported == "No":
        result_label = "FN"
    elif expected == "Safe" and reported == "Yes":
        result_label = "FP"
    else:
        result_label = "TN"

    rows.append([file, expected, reported, result_label])

headers = ["File", "Expected", "Reported", "Result"]
widths = [len(h) for h in headers]

for row in rows:
    for i, value in enumerate(row):
        widths[i] = max(widths[i], len(value))

def format_row(row):
    return " | ".join(value.ljust(widths[i]) for i, value in enumerate(row))

print(format_row(headers))
print("-+-".join("-" * w for w in widths))

for row in rows:
    print(format_row(row))

tp = sum(1 for row in rows if row[3] == "TP")
tn = sum(1 for row in rows if row[3] == "TN")
fp = sum(1 for row in rows if row[3] == "FP")
fn = sum(1 for row in rows if row[3] == "FN")

precision = tp / (tp + fp) if tp + fp > 0 else 0
recall = tp / (tp + fn) if tp + fn > 0 else 0
accuracy = (tp + tn) / (tp + tn + fp + fn)

print()
print(f"TP: {tp}, TN: {tn}, FP: {fp}, FN: {fn}")
print(f"Accuracy: {accuracy:.2%}")
print(f"Precision: {precision:.2%}")
print(f"Recall: {recall:.2%}")