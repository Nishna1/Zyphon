"""
web_log_analyzer.py - parses Nginx/Apache access logs and flags suspicious activity.
"""

import re
from collections import defaultdict
from urllib.parse import unquote

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


def analyze(logfile_path, threshold=50):
    requests_per_ip = defaultdict(int)
    status_404_per_ip = defaultdict(int)
    signature_hits = []

    with open(logfile_path, "r", errors="ignore") as f:
        for line_num, line in enumerate(f, start=1):
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
                    signature_hits.append((ip, path, description, line_num))

    alerts = []

    for ip, count in requests_per_ip.items():
        if count >= threshold:
            alerts.append({
                "severity": "MEDIUM",
                "rule": "High Request Volume",
                "source_ip": ip,
                "details": f"{count} requests — possible scanning or DoS activity",
            })

    for ip, count in status_404_per_ip.items():
        if count >= 10:
            alerts.append({
                "severity": "MEDIUM",
                "rule": "Path Brute Forcing",
                "source_ip": ip,
                "details": f"{count} requests returned 404 — possible directory/path enumeration",
            })

    for ip, path, description, line_num in signature_hits:
        alerts.append({
            "severity": "HIGH",
            "rule": description,
            "source_ip": ip,
            "details": f"Request path: {path} (line {line_num})",
        })

    return alerts


