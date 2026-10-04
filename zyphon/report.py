"""
report.py - formats and outputs alerts (console + JSON).
"""

import json

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}


def print_alerts(alerts):
    if not alerts:
        print("[*] No alerts triggered. Log looks clean against current rules.")
        return

    alerts_sorted = sorted(alerts, key=lambda a: SEVERITY_ORDER.get(a["severity"], 99))

    print(f"[*] {len(alerts_sorted)} alert(s) found:\n")
    for alert in alerts_sorted:
        icon = SEVERITY_ICON.get(alert["severity"], "")
        print(f"{icon} [{alert['severity']}] {alert['rule']}")
        print(f"    Source IP : {alert['source_ip']}")
        print(f"    Details   : {alert['details']}")
        print()

    counts = {}
    for a in alerts_sorted:
        counts[a["severity"]] = counts.get(a["severity"], 0) + 1
    summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 99)))
    print(f"[*] Summary: {summary}")


def save_json(alerts, output_path):
    with open(output_path, "w") as f:
        json.dump(alerts, f, indent=2)



