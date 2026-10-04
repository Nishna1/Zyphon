"""
auth_log_analyzer.py - parses Linux auth.log style files and flags:
  - Brute-force SSH login attempts
  - Successful login immediately after a burst of failures
  - Invalid user enumeration attempts
"""

import re
from collections import defaultdict

FAILED_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def analyze(logfile_path, threshold=5):
    failed_attempts = defaultdict(list)
    invalid_users = defaultdict(set)
    accepted_logins = []

    with open(logfile_path, "r", errors="ignore") as f:
        for line_num, line in enumerate(f, start=1):
            m = FAILED_RE.search(line)
            if m:
                ip = m.group("ip")
                user = m.group("user")
                failed_attempts[ip].append(user)
                continue

            m = INVALID_USER_RE.search(line)
            if m:
                invalid_users[m.group("ip")].add(m.group("user"))
                continue

            m = ACCEPTED_RE.search(line)
            if m:
                accepted_logins.append((m.group("ip"), m.group("user"), line_num))

    alerts = []

    for ip, attempts in failed_attempts.items():
        if len(attempts) >= threshold:
            alerts.append({
                "severity": "HIGH",
                "rule": "Brute Force SSH Attempt",
                "source_ip": ip,
                "details": f"{len(attempts)} failed login attempts "
                           f"(usernames tried: {', '.join(sorted(set(attempts))[:10])})",
            })

    for ip, users in invalid_users.items():
        if len(users) >= 3:
            alerts.append({
                "severity": "MEDIUM",
                "rule": "Username Enumeration",
                "source_ip": ip,
                "details": f"Tried {len(users)} invalid usernames: {', '.join(sorted(users)[:10])}",
            })

    flagged_ips = {ip for ip, attempts in failed_attempts.items() if len(attempts) >= threshold}
    for ip, user, line_num in accepted_logins:
        if ip in flagged_ips:
            alerts.append({
                "severity": "CRITICAL",
                "rule": "Successful Login After Brute Force",
                "source_ip": ip,
                "details": f"Login succeeded as '{user}' (line {line_num}) after "
                           f"{len(failed_attempts[ip])} prior failed attempts — possible compromise",
            })

    return alerts
