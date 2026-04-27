# Secret Log Checker

A static analysis tool built with Pysa (Pyre) to detect **sensitive data leakage into logging statements** in Python applications.

---

## Overview

Logging is essential for debugging and observability, but accidentally logging secrets (e.g., passwords, API keys) can lead to serious security risks.

This project uses **taint analysis** to detect flows where:
- **Sensitive data (sources)**  flows into  --> **Logging functions (sinks)**

---

## Project Structure
```
secret-log-checker/
│
├── app/
│   └── example.py              # Example Python code
│
├── stubs/
│   └── taint/
│       └── secrets_to_logs/
│           ├── taint.config    # Sources, sinks, rules
│           └── models.pysa     # Function modeling
│
├── .pyre_configuration         # Pyre/Pysa config
├── .gitignore
└── README.md
```
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
    1. `pyre analyze`