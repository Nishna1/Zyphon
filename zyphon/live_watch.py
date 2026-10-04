"""
live_watch.py - tails a log file like `tail -f` and raises alerts the moment
a new suspicious line appears, instead of waiting to analyze a finished file.

Uses the same detection patterns as auth_log_analyzer.py / web_log_analyzer.py,
but tracks state incrementally line-by-line so it can alert in real time.
"""

import re
import time
from collections import defaultdict
from urllib.parse import unquote

from zyphon.report import SEVERITY_ICON

# --- Auth log patterns ---
FAILED_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# --- Web log patterns ---
LOG_LINE_RE = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d+)\s+\S+'
)
SUSPICIOUS_PATTERNS = [
    (re.compile(r"union\s+select", re.IGNORECASE), "Possible SQL injection pattern"),
    (re.compile(r"<script", re.IGNORECASE), "Possible XSS pattern"),
    (re.compile(r"\.\./\.\./", re.IGNORECASE), "Possible path traversal"),
    (re.compile(r"/etc/passwd", re.IGNORECASE), "Possible local file inclusion attempt"),
    (re.compile(r"(?:%27|%22|'|\")\s*(?:or|and)\s", re.IGNORECASE), "Possible SQLi boolean injection"),
]


def _print_alert(severity, rule, source_ip, details):
    icon = SEVERITY_ICON.get(severity, "")
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {icon} [{severity}] {rule}")
    print(f"    Source IP : {source_ip}")
    print(f"    Details   : {details}")
    print()


def _follow(filepath, from_start):
    """Generator that yields new lines as they're appended to the file,
    like `tail -f`."""
    with open(filepath, "r", errors="ignore") as f:
        if not from_start:
            f.seek(0, 2)  # jump to end of file — only watch NEW lines
        while True:
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(0.5)


def watch_auth(filepath, threshold=5, from_start=False):
    print(f"[*] Watching {filepath} (auth log mode, threshold={threshold})")
    print("[*] Waiting for new log lines... (Ctrl+C to stop)\n")

    failed_attempts = defaultdict(list)
    invalid_users = defaultdict(set)
    already_alerted_bruteforce = set()
    already_alerted_enum = set()

    for line in _follow(filepath, from_start):
        m = FAILED_RE.search(line)
        if m:
            ip, user = m.group("ip"), m.group("user")
            failed_attempts[ip].append(user)
            if len(failed_attempts[ip]) >= threshold and ip not in already_alerted_bruteforce:
                already_alerted_bruteforce.add(ip)
                _print_alert(
                    "HIGH", "Brute Force SSH Attempt", ip,
                    f"{len(failed_attempts[ip])} failed login attempts "
                    f"(usernames tried: {', '.join(sorted(set(failed_attempts[ip]))[:10])})",
                )
            continue

        m = INVALID_USER_RE.search(line)
        if m:
            ip, user = m.group("ip"), m.group("user")
            invalid_users[ip].add(user)
            if len(invalid_users[ip]) >= 3 and ip not in already_alerted_enum:
                already_alerted_enum.add(ip)
                _print_alert(
                    "MEDIUM", "Username Enumeration", ip,
                    f"Tried {len(invalid_users[ip])} invalid usernames: "
                    f"{', '.join(sorted(invalid_users[ip])[:10])}",
                )
            continue

        m = ACCEPTED_RE.search(line)
        if m:
            ip, user = m.group("ip"), m.group("user")
            if ip in already_alerted_bruteforce:
                _print_alert(
                    "CRITICAL", "Successful Login After Brute Force", ip,
                    f"Login succeeded as '{user}' after "
                    f"{len(failed_attempts[ip])} prior failed attempts — possible compromise",
                )


def watch_web(filepath, threshold=50, from_start=False):
    print(f"[*] Watching {filepath} (web log mode, volume threshold={threshold})")
    print("[*] Waiting for new log lines... (Ctrl+C to stop)\n")

    requests_per_ip = defaultdict(int)
    status_404_per_ip = defaultdict(int)
    already_alerted_volume = set()
    already_alerted_404 = set()

    for line in _follow(filepath, from_start):
        m = LOG_LINE_RE.search(line)
        if not m:
            continue

        ip = m.group("ip")
        path = m.group("path")
        decoded_path = unquote(path)
        status = m.group("status")

        requests_per_ip[ip] += 1
        if status == "404":
            status_404_per_ip[ip] += 1

        for pattern, description in SUSPICIOUS_PATTERNS:
            if pattern.search(decoded_path):
                _print_alert("HIGH", description, ip, f"Request path: {path}")

        if requests_per_ip[ip] >= threshold and ip not in already_alerted_volume:
            already_alerted_volume.add(ip)
            _print_alert(
                "MEDIUM", "High Request Volume", ip,
                f"{requests_per_ip[ip]} requests — possible scanning or DoS activity",
            )

        if status_404_per_ip[ip] >= 10 and ip not in already_alerted_404:
            already_alerted_404.add(ip)
            _print_alert(
                "MEDIUM", "Path Brute Forcing", ip,
                f"{status_404_per_ip[ip]} requests returned 404 — possible directory/path enumeration",
            )
