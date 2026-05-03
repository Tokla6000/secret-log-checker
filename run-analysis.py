import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

from generate_models import SKIP_DIR_NAMES, main as generate_models


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Secret Log Checker analysis.")
    parser.add_argument(
        "--benchmark-cases",
        action="store_true",
        help="Run the benchmark cases.",
    )
    parser.add_argument(
        "--repo",
        help="Path to a repo to analyze (defaults to running benchmarks).",
    )
    return parser.parse_args()


ROOT_DIR = Path(__file__).resolve().parent
RESULTS_DIR = ROOT_DIR / "results"
PYSA_ROOT = ROOT_DIR / "pysa"
PYSA_MODELS_DIR = PYSA_ROOT / "models"
PYSA_TAINT_CONFIG = PYSA_ROOT / "taint.config"

BENCHMARK_ROOT = ROOT_DIR / "benchmarks"
BENCHMARK_CASES_ROOT = BENCHMARK_ROOT / "cases"
BENCHMARK_EXPECTED = BENCHMARK_ROOT / "expected.yaml"


def _extract_json_list(payload: str) -> str | None:
    start = payload.find("[")
    if start == -1:
        return None

    depth = 0
    end = None

    for i in range(start, len(payload)):
        if payload[i] == "[":
            depth += 1
        elif payload[i] == "]":
            depth -= 1
            if depth == 0:
                end = i
                break

    if end is None:
        return None
    return payload[start:end + 1]


def _parse_issue_list(payload: str) -> list[dict[str, object]] | None:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return None
    if isinstance(data, list) and all(isinstance(item, dict) for item in data):
        return data
    return None


# Extract issues
def extract_issues(stdout: str, stderr: str) -> list[dict[str, object]]:
    trimmed_stdout = stdout.strip()
    if trimmed_stdout:
        parsed = _parse_issue_list(trimmed_stdout)
        if parsed is not None:
            return parsed

        json_str = _extract_json_list(trimmed_stdout)
        if json_str:
            parsed = _parse_issue_list(json_str)
            if parsed is not None:
                return parsed

    print("[Output Error] No valid Pysa JSON emitted.")
    if trimmed_stdout:
        print("[STDOUT]\n" + trimmed_stdout)
    trimmed_stderr = stderr.strip()
    if trimmed_stderr:
        print("[STDERR]\n" + trimmed_stderr)
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


def format_box_table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        for i, value in enumerate(row):
            widths[i] = max(widths[i], len(value))

    def border() -> str:
        return "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def format_row(row: list[str]) -> str:
        return "|" + "|".join(f" {value.ljust(widths[i])} " for i, value in enumerate(row)) + "|"

    lines = [border(), format_row(headers), border()]
    lines.extend(format_row(row) for row in rows)
    lines.append(border())
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
    with tempfile.TemporaryDirectory(prefix="secret-log-checker-pysa-") as results_dir:
        result = subprocess.run(
            [
                str(pyre_executable),
                "analyze",
                "--save-results-to",
                results_dir,
                "--output-format",
                "json",
            ],
            capture_output=True,
            text=True,
            cwd=str(cwd) if cwd else None,
        )
        taint_output_path = Path(results_dir) / "taint-output.json"
        detailed_issues = load_taint_output_issues(taint_output_path)
        if taint_output_path.exists():
            return detailed_issues
        return extract_issues(result.stdout, result.stderr)


def analysis_roots_for(repo_path: Path) -> list[Path]:
    child_roots = [
        child
        for child in sorted(repo_path.iterdir())
        if child.is_dir()
        and child.name not in SKIP_DIR_NAMES
        and any(child.rglob("*.py"))
    ]
    if any(not child.name.isidentifier() for child in child_roots):
        return child_roots
    return [repo_path]


def build_pyre_excludes() -> list[str]:
    return [rf"(^|.*/){re.escape(name)}/.*" for name in sorted(SKIP_DIR_NAMES)]


def load_taint_output_issues(path: Path) -> list[dict[str, object]]:
    issues: list[dict[str, object]] = []
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return issues

    for line in lines:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict) or item.get("kind") != "issue":
            continue
        data = item.get("data")
        if not isinstance(data, dict):
            continue
        issue = dict(data)
        filename = issue.get("filename")
        if isinstance(filename, str) and "path" not in issue:
            issue["path"] = filename
        issues.append(issue)
    return issues


def normalize_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT_DIR.resolve()).as_posix()
    except (OSError, ValueError):
        return path.as_posix()


def issue_path(issue: dict[str, object]) -> str:
    raw = issue.get("path")
    if not isinstance(raw, str):
        return "?"
    path = Path(raw)
    if not path.is_absolute():
        path = ROOT_DIR / path
    return normalize_path(path)


def issue_source_sink(issue: dict[str, object]) -> tuple[str, str]:
    source = "?"
    sink = "?"
    sources = issue.get("sources")
    sinks = issue.get("sinks")
    if isinstance(sources, list) and sources:
        entry = sources[0]
        if isinstance(entry, dict):
            name = entry.get("name")
            if isinstance(name, str):
                source = name
    if isinstance(sinks, list) and sinks:
        entry = sinks[0]
        if isinstance(entry, dict):
            name = entry.get("name")
            if isinstance(name, str):
                sink = name
    traces = issue.get("traces")
    if isinstance(traces, list):
        for trace in traces:
            if not isinstance(trace, dict):
                continue
            trace_name = trace.get("name")
            trace_leaf = first_trace_leaf(trace, include_port=trace_name == "forward")
            if trace_name == "forward" and trace_leaf:
                source = trace_leaf
            elif trace_name == "backward" and trace_leaf:
                sink = trace_leaf
    sink_handle = issue.get("sink_handle")
    if sink == "?" and isinstance(sink_handle, dict):
        callee = sink_handle.get("callee")
        if isinstance(callee, str):
            sink = callee
    return source, sink


def first_trace_leaf(trace: dict[str, object], include_port: bool = False) -> str | None:
    roots = trace.get("roots")
    if not isinstance(roots, list):
        return None

    for root in roots:
        if not isinstance(root, dict):
            continue
        kinds = root.get("kinds")
        if not isinstance(kinds, list):
            continue
        for kind in kinds:
            if not isinstance(kind, dict):
                continue
            leaves = kind.get("leaves")
            if isinstance(leaves, list):
                for leaf in leaves:
                    if not isinstance(leaf, dict):
                        continue
                    name = leaf.get("name")
                    port = leaf.get("port")
                    if not isinstance(name, str):
                        continue
                    name = unwrap_pysa_object_name(name)
                    if include_port and isinstance(port, str) and port.startswith("leaf:") and port != "leaf:return":
                        return f"{name}.{port.removeprefix('leaf:')}"
                    return name
            kind_name = kind.get("kind")
            if isinstance(kind_name, str):
                return unwrap_pysa_object_name(kind_name)
    return None


def unwrap_pysa_object_name(name: str) -> str:
    if name.startswith("Obj{") and name.endswith("}"):
        return name[4:-1]
    return name


# Repo analysis 
def run_repo_analysis(pyre_executable: Path, repo_path: Path, source_roots: list[Path]) -> None:
    config_path = repo_path / ".pyre_configuration"
    created_config = False
    pyre_dir = repo_path / ".pyre"
    had_pyre_dir = pyre_dir.exists()

    if not config_path.exists():
        models_path = PYSA_ROOT
        config = {
            "source_directories": [
                root.relative_to(repo_path).as_posix() if root != repo_path else "."
                for root in source_roots
            ],
            "taint_models_path": str(models_path),
            "excludes": build_pyre_excludes(),
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

    issues = data
    rows = []
    findings: list[dict[str, object]] = []

    for issue in issues:
        line = issue.get("line")
        line_value = int(line) if isinstance(line, int) else line
        source, sink = issue_source_sink(issue)
        path = issue_path(issue)
        rows.append([path, str(line_value if line_value is not None else "?"), source, sink])
        findings.append(
            {
                "file": path,
                "line": line_value,
                "source": source,
                "sink": sink,
            }
        )

    title = "Static Secret-to-Log Checker Report"
    print()
    print(title)
    print("=" * len(title))
    print()
    print(f"Target repository: {repo_path}")
    print()

    if rows:
        headers = ["File", "Line", "Source", "Sink"]
        print(format_box_table(headers, rows))
    else:
        print("No issues found.")

    print()
    print(f"Total Possible Issues: {len(issues)}")

    results = {
        "mode": "repo",
        "target": str(repo_path),
        "total": len(issues),
        "issues": findings,
    }
    save_results(results, "repo")


# Benchmark analysis 
def parse_expected_cases(path: Path) -> dict[str, dict[str, object]]:
    content = path.read_text().splitlines()
    cases: dict[str, dict[str, object]] = {}
    current_case: str | None = None
    in_cases = False

    for raw_line in content:
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.strip() == "cases:":
            in_cases = True
            continue
        if not in_cases:
            continue

        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if indent == 2 and stripped.endswith(":"):
            current_case = stripped[:-1]
            cases[current_case] = {}
            continue
        if current_case and indent >= 4 and ":" in stripped:
            key, value = stripped.split(":", 1)
            value = value.strip()
            parsed: object
            if value.lower() in {"true", "false"}:
                parsed = value.lower() == "true"
            elif value.isdigit():
                parsed = int(value)
            else:
                parsed = value.strip('"')
            cases[current_case][key] = parsed

    return cases


def resolve_case_path(raw: str) -> Path:
    candidate = ROOT_DIR / raw
    if candidate.exists():
        return candidate
    if raw.startswith("benchmarks/"):
        suffix = raw[len("benchmarks/"):]
        candidate = BENCHMARK_CASES_ROOT / suffix
        if candidate.exists():
            return candidate
    candidate = BENCHMARK_CASES_ROOT / raw
    return candidate


def summarize_category(cases: list[dict[str, object]]) -> tuple[int, int, int, int]:
    tp = sum(1 for case in cases if case["classification"] == "TP")
    fp = sum(1 for case in cases if case["classification"] == "FP")
    fn = sum(1 for case in cases if case["classification"] == "FN")
    tn = sum(1 for case in cases if case["classification"] == "TN")
    return tp, fp, fn, tn


def format_ratio(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.2f}"


def run_benchmark_cases(pyre_executable: Path) -> None:
    config_path = ROOT_DIR / ".pyre_configuration"
    original_config: str | None = None
    pyre_dir = ROOT_DIR / ".pyre"
    had_pyre_dir = pyre_dir.exists()

    config = {
        "source_directories": [str(BENCHMARK_ROOT)],
        "taint_models_path": str(PYSA_ROOT),
    }
    if config_path.exists():
        original_config = config_path.read_text()
    config_path.write_text(json.dumps(config, indent=2) + "\n")

    try:
        issues = run_pyre_analyze(pyre_executable)
    finally:
        if original_config is None:
            try:
                config_path.unlink()
            except OSError:
                pass
        else:
            try:
                config_path.write_text(original_config)
            except OSError:
                pass
        if not had_pyre_dir and pyre_dir.exists():
            shutil.rmtree(pyre_dir, ignore_errors=True)

    expected_cases = parse_expected_cases(BENCHMARK_EXPECTED)
    reported_files = {issue_path(issue) for issue in issues}

    case_results: list[dict[str, object]] = []
    for case_id, data in expected_cases.items():
        raw_file = data.get("file")
        if not isinstance(raw_file, str):
            continue
        case_path = resolve_case_path(raw_file)
        normalized_path = normalize_path(case_path)
        expected = bool(data.get("expected_leak"))
        detected = normalized_path in reported_files
        if expected and detected:
            classification = "TP"
        elif expected and not detected:
            classification = "FN"
        elif not expected and detected:
            classification = "FP"
        else:
            classification = "TN"

        case_results.append(
            {
                "id": case_id,
                "file": normalized_path,
                "expected": expected,
                "detected": detected,
                "classification": classification,
                "category": str(data.get("category", "unknown")),
                "source": str(data.get("source", "?")),
                "sink": str(data.get("sink", "?")),
                "sanitizer": data.get("sanitizer"),
            }
        )

    categories = {
        "direct": "Direct leaks",
        "formatting": "String formatting",
        "cross_function": "Cross-function flows",
        "sanitizer": "Sanitized cases",
    }

    category_rows: list[list[str]] = []
    for key, label in categories.items():
        category_cases = [case for case in case_results if case["category"] == key]
        tp, fp, fn, _ = summarize_category(category_cases)
        positive_cases = sum(1 for case in category_cases if case["expected"])
        precision = tp / (tp + fp) if tp + fp > 0 else None
        recall = tp / (tp + fn) if tp + fn > 0 else None
        f1 = None
        if precision is not None and recall is not None and (precision + recall) > 0:
            f1 = 2 * precision * recall / (precision + recall)

        category_rows.append(
            [
                label,
                str(len(category_cases)),
                str(tp),
                str(fp),
                format_ratio(precision if positive_cases > 0 else None),
                format_ratio(recall if positive_cases > 0 else None),
                format_ratio(f1 if positive_cases > 0 else None),
            ]
        )

    tp = sum(1 for case in case_results if case["classification"] == "TP")
    fp = sum(1 for case in case_results if case["classification"] == "FP")
    fn = sum(1 for case in case_results if case["classification"] == "FN")
    tn = sum(1 for case in case_results if case["classification"] == "TN")
    precision = tp / (tp + fp) if tp + fp > 0 else 0.0
    recall = tp / (tp + fn) if tp + fn > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    title = "Static Secret-to-Log Checker Evaluation"
    print()
    print(title)
    print("=" * len(title))
    print()
    print("Dataset: Benchmark Cases")
    print()
    headers = [
        "Category",
        "Cases",
        "TP",
        "FP",
        "Precision",
        "Recall",
        "F1",
    ]
    print(format_box_table(headers, category_rows))
    print()
    print("Overall:")
    print(f"  True Positives: {tp}")
    print(f"  False Positives: {fp}")
    print(f"  False Negatives: {fn}")
    print(f"  True Negatives: {tn}")
    print(f"  Precision: {precision:.2f}")
    print(f"  Recall:    {recall:.2f}")
    print(f"  F1:        {f1:.2f}")

    results = {
        "mode": "benchmark",
        "dataset": "benchmark_cases",
        "summary": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(precision, 2),
            "recall": round(recall, 2),
            "f1": round(f1, 2),
        },
        "findings": case_results,
    }
    save_results(results, "benchmark")


def save_results(payload: dict[str, object], mode: str) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_path = RESULTS_DIR / f"{mode}-results-{timestamp}.json"
    output_path.write_text(json.dumps(payload, indent=2) + "\n")


def main() -> None:
    args = parse_args()

    if args.repo and args.benchmark_cases:
        print("Please choose either --repo or --benchmark-cases, not both.")
        raise SystemExit(2)

    repo_path = None
    if args.repo:
        repo_path = Path(args.repo).expanduser().resolve()
        if not repo_path.exists():
            print(f"Repo path not found: {repo_path}")
            raise SystemExit(1)

    if repo_path:
        source_roots = analysis_roots_for(repo_path)
        generate_models(scan_roots_override=source_roots)
    else:
        source_roots = []
        generate_models()

    pyre_executable = Path(sys.executable).with_name("pyre")
    if not pyre_executable.exists():
        raise FileNotFoundError(f"Could not find Pyre executable at {pyre_executable}")

    if repo_path:
        run_repo_analysis(pyre_executable, repo_path, source_roots)
    else:
        run_benchmark_cases(pyre_executable)


if __name__ == "__main__":
    main()
