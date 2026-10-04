# SOC Alert Toolkit

A lightweight, dependency-free log analysis and alerting tool for SOC-analyst
practice. Parses standard log formats and flags suspicious activity using
simple, explainable detection rules — the same kind of logic a SIEM uses
under the hood, just transparent and hand-rolled so you can see exactly why
each alert fires.

## What it detects

**Auth logs** (`--type auth`, Linux `auth.log` / sshd format):
- Brute-force SSH login attempts (repeated failures from one IP)
- Username enumeration (many different invalid usernames tried)
- Successful login immediately following a burst of failures — flagged as
  a possible compromise

**Web logs** (`--type web`, Nginx/Apache combined log format):
- High request volume from a single IP (possible scanning/DoS)
- Path brute forcing (many 404s from one IP — directory enumeration)
- Known attack-signature patterns in request paths: SQL injection, XSS,
  path traversal, local file inclusion attempts

## Why this design

Each rule is a small, readable function — the point is to understand why
an alert fires, not just see a pass/fail result. That's the actual skill a
SOC analyst role tests for: reading a rule, explaining the false-positive
rate, and knowing how you'd tune the threshold.

## Install

```bash
git clone https://github.com/nishna1/soc-alert-toolkit.git
cd soc-alert-toolkit
pip install -e .
```

## Usage

```bash
# Analyze an auth log
soc-alert analyze sample_logs/sample_auth.log --type auth

# Analyze a web access log
soc-alert analyze sample_logs/sample_access.log --type web --threshold 10

# Adjust the failed-attempt threshold
soc-alert analyze /var/log/auth.log --type auth --threshold 3

# Save alerts as JSON
soc-alert analyze /var/log/auth.log --type auth -o alerts.json
```

Sample logs are included in `sample_logs/` so you can try it immediately.

## Project structure
soc-alert-toolkit/
├── soc_alert/
│ ├── init.py
│ ├── cli.py
│ ├── auth_log_analyzer.py
│ ├── web_log_analyzer.py
│ └── report.py
├── sample_logs/
│ ├── sample_auth.log
│ └── sample_access.log
├── setup.py
└── README.md



## Author

Nishna Rayamajhi


