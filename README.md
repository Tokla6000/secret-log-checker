# Secret Log Checker

A Python static analysis tool that uses Pyre/Pysa taint analysis to find sensitive values flowing into logging or debug output.

The checker models values such as passwords, tokens, API keys, credentials, and secrets as taint sources. It reports when those values can reach logging-style sinks such as `logging.info`, `logger.debug`, `print`, `pprint.pprint`, or `warnings.warn`.

## What It Does

- Runs Pysa against either the included benchmark suite or a target Python repository.
- Generates Pysa models before each run based on the code being analyzed.
- Reports possible secret-to-log flows in a terminal table.
- Writes JSON result files under `results/`.

## Project Layout

```text
.
├── run-analysis.py              
├── generate_models.py          
├── requirements.txt             
├── Dockerfile                   
├── pysa/
│   ├── taint.config             
│   └── models/
│       ├── base_models.pysa    
│       ├── generated_models.pysa 
│       └── models.pysa          
├── benchmarks/
│   ├── cases/                   
│   └── expected.yaml            
├── example_repos/                           
└── results/                     
```

## Requirements

- Python 3.10 is recommended
- `pip`


## Docker Usage

Build the image:

```bash
docker build -t secret-log-checker .
```

Run TUI interface:

```bash
docker run --rm -it secret-log-checker tui.py
```

## Local Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Usage

Run the included benchmark cases.
The tool runs the benchmark cases by default.

```bash
python run-analysis.py --benchmark-cases
```

Analyze another Python repository:

```bash
python run-analysis.py --repo /path/to/python/repo
```

OR use the handy TUI interface

```bash
python tui.py
```


## Output

Benchmark mode prints a summary table grouped by case category:

```text
Static Secret-to-Log Checker Evaluation
=======================================

Dataset: Benchmark Cases

+----------------------+-------+----+----+-----------+--------+------+
| Category             | Cases | TP | FP | Precision | Recall | F1   |
+----------------------+-------+----+----+-----------+--------+------+
| Direct leaks         | ...   | .. | .. | ...       | ...    | ...  |
| String formatting    | ...   | .. | .. | ...       | ...    | ...  |
| Cross-function flows | ...   | .. | .. | ...       | ...    | ...  |
| Sanitized cases      | ...   | .. | .. | ...       | ...    | ...  |
+----------------------+-------+----+----+-----------+--------+------+
```

Repository mode prints each possible issue:

```text
Static Secret-to-Log Checker Report
===================================

Target repository: /path/to/python/repo

+----------+------+--------+--------------+
| File     | Line | Source | Sink         |
+----------+------+--------+--------------+
| app.py   | 12   | token  | logging.info |
+----------+------+--------+--------------+

Total Possible Issues: 1
```

Each run also saves a JSON file in `results/`

## Model Generation

`run-analysis.py` calls `generate_models.py` before running Pysa.

The generator scans Python files and writes `pysa/models/generated_models.pysa`, then merges it with `pysa/models/base_models.pysa` into `pysa/models/models.pysa`.

Generated source models include:

- Functions with suspicious names such as `secret`, `token`, `password`, `passwd`, `api_key`, `credential`, `private_key`, or `config`.
- Global variables and attributes with suspicious names.
- Functions that return sensitive values from request-like mappings.
- Mapping accesses for sensitive keys such as `password`, `token`, `secret`, `api_key`, and `credential`.

Generated sanitizer models include simple masking, redaction, hashing, `len(...)`, and `bool(...)` patterns when the function consistently returns only the sanitized form.

## Benchmark Suite

The benchmark cases live in `benchmarks/cases/` and are grouped into:

- Direct leaks
- String formatting leaks
- Cross-function flows
- Sanitized cases

Expected classifications are defined in `benchmarks/expected.yaml`.

## Notes
