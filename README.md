# Secret to Log Checker

A static analysis tool built with Pysa (Pyre) to detect **sensitive data leakage into logging statements** in Python applications.

---

## Overview

Logging is essential for debugging and observability, but accidentally logging secrets (e.g., passwords, API keys) can lead to serious security risks.

This project uses **taint analysis** to detect flows where:

- **Sensitive data (sources)** flows into --> **Logging functions (sinks)**

---

## Project Structure

```
TODO REDO
```

## Benchmarks

TODO REDO

## Setup Instructions

Prerequisites

- Python 3.9 – 3.12 (recommended: 3.10)
- pip

1. Clone the repo
1. Create virtual environment
   1. `python3 -m venv .venv`
   1. `source .venv/bin/activate`
1. Install dependencies
   1. `pip install --upgrade pip`
   1. `pip install -r requirements.txt`
1. Run the analysis
   1. TODO: change to differnt options

## Model Pipeline

TODO: update / refactor

<!--
`generate_models.py` now manages a three-step model pipeline:

1. Stable hand-written models live in `stubs/taint_templates/secrets_to_logs/base_models.pysa`
2. Auto-discovered models are written to `stubs/taint_templates/secrets_to_logs/generated_models.pysa`
3. Both are merged into `stubs/taint/secrets_to_logs/models.pysa` (the single file Pysa reads)

The generator scans `app/` and `benchmarks/` for suspicious function names. If a function name contains one of these keywords, its return value is modeled as a secret source:

- `secret`
- `token`
- `password`
- `passwd`
- `api_key`
- `credential`
- `private_key`

Sanitizer-like names (`mask`, `redact`, `hash`, `sanitize`, `anonymize`, `scrub`) are also modeled automatically.

`run-analysis.py` calls `generate_models.py` automatically before `pyre analyze`. -->

### Output format

TODO:
if user runs "python run-analysis.py --benchmark-cases" we want output like this:

```
Static Secret-to-Log Checker Evaluation
======================================

Dataset: Synthetic Benchmark

+----------------------+-------+-------+-------+-----------+--------+------+
| Category             | Cases | TP    | FP    | Precision | Recall | F1   |
+----------------------+-------+-------+-------+-----------+--------+------+
| Direct leaks         | 10    | 10    | 0     | 1.00      | 1.00   | 1.00 |
| String formatting    | 8     | 7     | 1     | 0.88      | 0.88   | 0.88 |
| Cross-function flows | 8     | 6     | 0     | 1.00      | 0.75   | 0.86 |
| Sanitized cases      | 10    | 0     | 1     | -         | -      | -    |
+----------------------+-------+-------+-------+-----------+--------+------+

Overall:
  True Positives: 23
  False Positives: 2
  False Negatives: 3
  True Negatives: 22
  Precision: 0.92
  Recall:    0.88
  F1:        0.90
```

<!--
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1        = 2 * Precision * Recall / (Precision + Recall)
-->

TODO:
if user runs "python run-analysis.py --repo /path/to/own/repo" we want output like this:

```
Static Secret-to-Log Checker Report
===================================

Target repository: /path/to/own/repo

+------------------------------+------+------------------+------------------+
| File                         | Line | Source           | Sink             |
+------------------------------+------+------------------+------------------+
| app/auth.py                  | 42   | os.getenv        | logging.info     |
| services/payments.py         | 88   | get_secret       | logger.debug     |
| config_loader.py             | 31   | settings.SECRET  | app.logger.error |
+------------------------------+------+------------------+------------------+

Total Possible Issues: 3

```
