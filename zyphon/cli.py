#!/usr/bin/env python3
"""
zyphon - a lightweight log analysis & alerting tool for SOC-analyst practice.
"""

import argparse
import sys

from zyphon import auth_log_analyzer
from zyphon import web_log_analyzer
from zyphon import report
from zyphon import live_watch


def build_parser():
    parser = argparse.ArgumentParser(
        prog="zyphon",
        description="Log analysis and alerting tool for SOC analyst practice.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a log file and print alerts")
    analyze_parser.add_argument("logfile", help="Path to the log file")
    analyze_parser.add_argument(
        "--type", choices=["auth", "web"], required=True,
        help="Log type: 'auth' for /var/log/auth.log style, 'web' for access.log style"
    )
    analyze_parser.add_argument(
        "-o", "--output", default=None, help="Optional: save alerts as JSON to this path"
    )
    analyze_parser.add_argument(
        "--threshold", type=int, default=5,
        help="Failed-attempt threshold before flagging an IP (default: 5)"
    )

    watch_parser = subparsers.add_parser("watch", help="Watch a log file live and alert in real time")
    watch_parser.add_argument("logfile", help="Path to the log file to tail")
    watch_parser.add_argument(
        "--type", choices=["auth", "web"], required=True,
        help="Log type: 'auth' or 'web'"
    )
    watch_parser.add_argument(
        "--threshold", type=int, default=5,
        help="Failed-attempt / request-volume threshold (default: 5)"
    )
    watch_parser.add_argument(
        "--from-start", action="store_true",
        help="Process the whole file from the beginning instead of only new lines"
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "analyze":
            if args.type == "auth":
                alerts = auth_log_analyzer.analyze(args.logfile, threshold=args.threshold)
            else:
                web_threshold = args.threshold if args.threshold != 5 else 50
                alerts = web_log_analyzer.analyze(args.logfile, threshold=web_threshold)

            report.print_alerts(alerts)

            if args.output:
                report.save_json(alerts, args.output)
                print(f"\n[*] Alerts saved to {args.output}")

        elif args.command == "watch":
            if args.type == "auth":
                live_watch.watch_auth(args.logfile, threshold=args.threshold, from_start=args.from_start)
            else:
                web_threshold = args.threshold if args.threshold != 5 else 50
                live_watch.watch_web(args.logfile, threshold=web_threshold, from_start=args.from_start)
    except FileNotFoundError:
        print(f"[!] Log file not found: {args.logfile}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(130)


if __name__ == "__main__":
    main()
