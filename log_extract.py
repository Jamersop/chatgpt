#!/usr/bin/env python3
"""Extract relevant information from a log file.

The script scans each log line, tries to detect common fields,
and prints a concise JSON summary.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


TIMESTAMP_PATTERNS = [
    re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:,\d{3}|\.\d+)?\b"),
    re.compile(r"\b\d{2}/\d{2}/\d{4}[ T]\d{2}:\d{2}:\d{2}\b"),
]

LEVEL_PATTERN = re.compile(r"\b(DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL)\b", re.IGNORECASE)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_PATTERN = re.compile(r"\buser(?:name)?[=:]\s*([\w.@-]+)\b", re.IGNORECASE)
ERROR_CODE_PATTERN = re.compile(r"\b(?:error[_ -]?code|code)[=:]\s*([A-Z]?\d{2,6})\b", re.IGNORECASE)


def first_match(patterns: list[re.Pattern[str]], text: str) -> str | None:
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None


def extract(log_path: Path, sample_limit: int) -> dict:
    levels = Counter()
    ips = Counter()
    users = Counter()
    error_codes = Counter()

    timestamps = []
    total_lines = 0
    lines_with_errors = 0
    interesting_samples: dict[str, list[str]] = defaultdict(list)

    with log_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            total_lines += 1
            line = line.rstrip("\n")

            timestamp = first_match(TIMESTAMP_PATTERNS, line)
            if timestamp:
                timestamps.append(timestamp)

            level_match = LEVEL_PATTERN.search(line)
            if level_match:
                level = level_match.group(1).upper()
                if level == "WARNING":
                    level = "WARN"
                levels[level] += 1

            for ip in IP_PATTERN.findall(line):
                ips[ip] += 1

            user_match = USER_PATTERN.search(line)
            if user_match:
                users[user_match.group(1)] += 1

            code_match = ERROR_CODE_PATTERN.search(line)
            if code_match:
                error_codes[code_match.group(1)] += 1

            if "ERROR" in line.upper() or "EXCEPTION" in line.upper():
                lines_with_errors += 1
                if len(interesting_samples["errors"]) < sample_limit:
                    interesting_samples["errors"].append(line)

            if "timeout" in line.lower() and len(interesting_samples["timeouts"]) < sample_limit:
                interesting_samples["timeouts"].append(line)

            if "failed" in line.lower() and len(interesting_samples["failures"]) < sample_limit:
                interesting_samples["failures"].append(line)

    summary = {
        "file": str(log_path),
        "total_lines": total_lines,
        "lines_with_error_or_exception": lines_with_errors,
        "time_range": {
            "first_seen": timestamps[0] if timestamps else None,
            "last_seen": timestamps[-1] if timestamps else None,
        },
        "top_log_levels": levels.most_common(),
        "top_ips": ips.most_common(10),
        "top_users": users.most_common(10),
        "error_codes": error_codes.most_common(10),
        "samples": dict(interesting_samples),
    }
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract relevant information from logs")
    parser.add_argument("logfile", type=Path, help="Path to the input log file")
    parser.add_argument(
        "--sample-limit",
        type=int,
        default=5,
        help="Maximum number of sample lines to keep per category (default: 5)",
    )
    args = parser.parse_args()

    if not args.logfile.exists() or not args.logfile.is_file():
        raise SystemExit(f"Log file not found or not a regular file: {args.logfile}")

    result = extract(args.logfile, sample_limit=max(1, args.sample_limit))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
