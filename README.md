# Secret to Log Checker

A static analysis tool built with Pysa (Pyre) to detect **sensitive data leakage into logging statements** in Python applications.

---

## Overview

Logging is essential for debugging and observability, but accidentally logging secrets (e.g., passwords, API keys) can lead to serious security risks.

This project uses **taint analysis** to detect flows where:
- **Sensitive data (sources)**  flows into  --> **Logging functions (sinks)**

---

## Project Structure
```
app/                # example app
benchmarks/         # evaluation dataset
  safe/             # safe logging cases
  unsafe/           # leaking cases
helper.py           # shared helper functions (sources/sanitizers)
stubs/taint/        # Pysa models + taint.config
run-analysis.py     # CLI tool (runs pyre + prints table)
generate_models.py  # scans Python files and writes generated Pysa sources
Dockerfile          # reproducible environment
```

## Benchmarks

The `benchmarks/` folder contains curated test cases:

Unsafe (should be detected)
- direct logging of secrets
- f-string leaks
- string concatenation
- cross-function propagation
- return-value propagation
- environment variable leaks
- dictionary-based flows

Safe (should NOT be detected)
- constant messages
- non-secret values
- redacted values
- masked values
- hashed values

## Setup Instructions
Prerequisites
- Python 3.9 – 3.12 (recommended: 3.10)
- pip
1. Clone the repo
1. Create virtual environment
    1. `python3 -m venv .venv`
    1. `source .venv/bin/activate`
1. Install dependencies
    1. `pip install --upgrade pip setuptools wheel`
    1. `pip install pyre-check`
1. Run the analysis
    1. `python run-analysis.py`

## Model Pipeline

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

`run-analysis.py` calls `generate_models.py` automatically before `pyre analyze`.