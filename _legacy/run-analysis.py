import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from generate_models import main as generate_models


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Secret Log Checker analysis.")
    parser.add_argument(
        "--repo",
        help="Path to a repo to analyze (defaults to running benchmarks).",
    )
    return parser.parse_args()


# Extract issues 
def extract_issues(output: str) -> list[dict[str, object]]:
    start = output.find("[")
    if start == -1:
        print("[Output Error] No Pysa JSON emitted. Error:\n")
        print(output)
        raise SystemExit(1)

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
        print("[Output Error] Pysa JSON Output Format Mismatch")
        raise SystemExit(1)

    json_str = output[start:end + 1]
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        print("Could not parse JSON")
        print(output)
        raise SystemExit(1)


# Format output table
def format_table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        for i, value in enumerate(row):
            widths[i] = max(widths[i], len(value))

    def format_row(row: list[str]) -> str:
        return " | ".join(value.ljust(widths[i]) for i, value in enumerate(row))

    lines = [format_row(headers), "-+-".join("-" * w for w in widths)]
    lines.extend(format_row(row) for row in rows)
    return "\n".join(lines)


# Load rule messages 
def load_rule_messages(config_path: Path) -> dict[int, str]:
    try:
        data = json.loads(config_path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}

    messages: dict[int, str] = {}
    for rule in data.get("rules", []):
        code = rule.get("code")
        if isinstance(code, int):
            message = rule.get("message_format") or rule.get("message") or rule.get("name")
            if isinstance(message, str):
                messages[code] = message
    return messages


# Run pyre analyze 
def run_pyre_analyze(pyre_executable: Path, cwd: Path | None = None) -> list[dict[str, object]]:
    result = subprocess.run(
        [str(pyre_executable), "analyze"],
        capture_output=True,
        text=True,
        cwd=str(cwd) if cwd else None,
    )
    output = result.stdout + "\n" + result.stderr
    return extract_issues(output)


# Repo analysis 
def run_repo_analysis(pyre_executable: Path, repo_path: Path) -> None:
    config_path = repo_path / ".pyre_configuration"
    created_config = False
    pyre_dir = repo_path / ".pyre"
    had_pyre_dir = pyre_dir.exists()

    if not config_path.exists():
        models_path = Path(__file__).resolve().parent / "pysa-config"
        config = {
            "source_directories": ["."],
            "taint_models_path": str(models_path),
        }
        config_path.write_text(json.dumps(config, indent=2) + "\n")
        created_config = True

    try:
        data = run_pyre_analyze(pyre_executable, cwd=repo_path)
    finally:
        if created_config:
            try:
                config_path.unlink()
            except OSError:
                pass
        if not had_pyre_dir and pyre_dir.exists():
            shutil.rmtree(pyre_dir, ignore_errors=True)

    if not data:
        print("No issues found.")
        return

    rule_messages = load_rule_messages(Path("pysa-config/taint.config"))
    rows = []

    for issue in data:
        code_value = issue.get("code")
        code = code_value if isinstance(code_value, int) else None
        if code is None:
            try:
                code = int(str(code_value))
            except (TypeError, ValueError):
                code = None

        message = issue.get("message") or issue.get("description") or ""
        if not message and code is not None:
            message = rule_messages.get(code, f"Rule {code} triggered.")

        rows.append(
            [
                str(issue.get("path", "?")),
                str(issue.get("line", "?")),
                str(code_value if code_value is not None else "?"),
                str(message),
            ]
        )

    headers = ["Path", "Line", "Code", "Message"]
    print(format_table(headers, rows))


# Benchmark analysis 
def run_benchmarks(pyre_executable: Path) -> None:
    data = run_pyre_analyze(pyre_executable)
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
    print(format_table(headers, rows))

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


def main() -> None:
    args = parse_args()

    repo_path = None
    if args.repo:
        repo_path = Path(args.repo).expanduser().resolve()
        if not repo_path.exists():
            print(f"Repo path not found: {repo_path}")
            raise SystemExit(1)

    if repo_path:
        generate_models(scan_roots_override=[repo_path])
    else:
        generate_models()

    pyre_executable = Path(sys.executable).with_name("pyre")
    if not pyre_executable.exists():
        raise FileNotFoundError(f"Could not find Pyre executable at {pyre_executable}")

    if repo_path:
        run_repo_analysis(pyre_executable, repo_path)
    else:
        run_benchmarks(pyre_executable)


if __name__ == "__main__":
    main()