#!/usr/bin/env python3
"""Extract relevant information from a log file.

This module provides reusable helpers for both CLI and Streamlit usage.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

TIMESTAMP_PATTERNS = [
    re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:,\d{3}|\.\d+)?\b"),
    re.compile(r"\b\d{2}/\d{2}/\d{4}[ T]\d{2}:\d{2}:\d{2}\b"),
]

LEVEL_PATTERN = re.compile(r"\b(DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL)\b", re.IGNORECASE)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_PATTERN = re.compile(r"\buser(?:name)?[=:]\s*([\w.@-]+)\b", re.IGNORECASE)
ERROR_CODE_PATTERN = re.compile(r"\b(?:error[_ -]?code|code)[=:]\s*([A-Z]?\d{2,6})\b", re.IGNORECASE)

CRITICAL_TERMS = ("critical", "fatal", "panic", "outage", "data loss")
MAJOR_TERMS = ("error", "exception", "failed", "timeout")


def first_match(patterns: list[re.Pattern[str]], text: str) -> str | None:
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            return match.group(0)
    return None


def summarize_lines(lines: Iterable[str], source_name: str, sample_limit: int = 5) -> dict:
    levels = Counter()
    ips = Counter()
    users = Counter()
    error_codes = Counter()

    timestamps = []
    total_lines = 0
    lines_with_errors = 0
    interesting_samples: dict[str, list[str]] = defaultdict(list)
    highlighted_events: dict[str, list[str]] = defaultdict(list)

    for raw_line in lines:
        total_lines += 1
        line = raw_line.rstrip("\n")
        normalized = line.lower()

        timestamp = first_match(TIMESTAMP_PATTERNS, line)
        if timestamp:
            timestamps.append(timestamp)

        level_match = LEVEL_PATTERN.search(line)
        normalized_level = None
        if level_match:
            normalized_level = level_match.group(1).upper()
            if normalized_level == "WARNING":
                normalized_level = "WARN"
            levels[normalized_level] += 1

        for ip in IP_PATTERN.findall(line):
            ips[ip] += 1

        user_match = USER_PATTERN.search(line)
        if user_match:
            users[user_match.group(1)] += 1

        code_match = ERROR_CODE_PATTERN.search(line)
        if code_match:
            error_codes[code_match.group(1)] += 1

        if "error" in normalized or "exception" in normalized:
            lines_with_errors += 1
            if len(interesting_samples["errors"]) < sample_limit:
                interesting_samples["errors"].append(line)

        if "timeout" in normalized and len(interesting_samples["timeouts"]) < sample_limit:
            interesting_samples["timeouts"].append(line)

        if "failed" in normalized and len(interesting_samples["failures"]) < sample_limit:
            interesting_samples["failures"].append(line)

        is_critical = any(term in normalized for term in CRITICAL_TERMS) or normalized_level in {"CRITICAL", "FATAL"}
        is_major = any(term in normalized for term in MAJOR_TERMS) or normalized_level in {"ERROR", "WARN"}

        if is_critical and len(highlighted_events["critical"]) < sample_limit:
            highlighted_events["critical"].append(line)
        elif is_major and len(highlighted_events["major"]) < sample_limit:
            highlighted_events["major"].append(line)

    return {
        "file": source_name,
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
        "highlighted_events": {
            "critical_count": len(highlighted_events["critical"]),
            "major_count": len(highlighted_events["major"]),
            "critical": highlighted_events["critical"],
            "major": highlighted_events["major"],
        },
    }


def extract(log_path: Path, sample_limit: int) -> dict:
    with log_path.open("r", encoding="utf-8", errors="replace") as fh:
        return summarize_lines(fh, source_name=str(log_path), sample_limit=sample_limit)


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
