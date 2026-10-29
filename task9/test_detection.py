#!/usr/bin/env python3
"""Test a simple authentication-failure threshold rule using synthetic CSV data.

Uses only Python's standard library. The `test_case` column is a lab annotation
used to keep scenarios isolated; it would not be a production event field.
"""

from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent
RULE_PATH = BASE_DIR / "detection_rule.json"
EVENTS_PATH = BASE_DIR / "data" / "auth_logs.csv"
CASES_PATH = BASE_DIR / "data" / "test_cases.json"


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp and normalize it to UTC."""
    normalized = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError(f"Timestamp lacks timezone: {value!r}")
    return parsed.astimezone(timezone.utc)


def load_events(path: Path) -> list[dict[str, Any]]:
    required = {"test_case", "timestamp_utc", "source_ip", "username", "event_type", "result"}
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"CSV missing required columns: {', '.join(sorted(missing))}")
        for line_number, row in enumerate(reader, start=2):
            if not all((row.get(field) or "").strip() for field in required):
                raise ValueError(f"CSV line {line_number} contains an empty required field")
            row["_timestamp"] = parse_timestamp(row["timestamp_utc"])
            events.append(row)
    return events


def detect(events: list[dict[str, Any]], rule: dict[str, Any]) -> list[dict[str, Any]]:
    """Return one alert for each case/IP that reaches threshold in any rolling window."""
    scope = rule["scope"]
    threshold = int(rule["threshold"])
    window_seconds = int(rule["timeframe_seconds"])
    if threshold < 1 or window_seconds < 1:
        raise ValueError("Rule threshold and timeframe_seconds must both be positive")

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event[scope["event_type_field"]].lower() != scope["event_type_value"].lower():
            continue
        if event[scope["result_field"]].lower() != scope["failure_value"].lower():
            continue
        grouped[(event["test_case"], event[scope["source_ip_field"]])].append(event)

    alerts: list[dict[str, Any]] = []
    for (case_id, source_ip), group in sorted(grouped.items()):
        group.sort(key=lambda event: event["_timestamp"])
        left = 0
        for right, current in enumerate(group):
            while (current["_timestamp"] - group[left]["_timestamp"]).total_seconds() > window_seconds:
                left += 1
            count = right - left + 1
            if count >= threshold:
                window_events = group[left : right + 1]
                alerts.append(
                    {
                        "test_case": case_id,
                        "source_ip": source_ip,
                        "failure_count": count,
                        "window_start": window_events[0]["timestamp_utc"],
                        "window_end": current["timestamp_utc"],
                        "user_count": len({event["username"] for event in window_events}),
                    }
                )
                break  # One representative alert per case/IP is enough for this test harness.
    return alerts


def main() -> int:
    try:
        rule = json.loads(RULE_PATH.read_text(encoding="utf-8"))
        test_cases = json.loads(CASES_PATH.read_text(encoding="utf-8"))
        events = load_events(EVENTS_PATH)
        unknown_cases = {event["test_case"] for event in events} - set(test_cases)
        missing_cases = set(test_cases) - {event["test_case"] for event in events}
        if unknown_cases or missing_cases:
            raise ValueError(
                f"Scenario mismatch; unknown={sorted(unknown_cases)}, no_events={sorted(missing_cases)}"
            )
        alerts = detect(events, rule)
        alerted_cases = {alert["test_case"] for alert in alerts}

        print(f"Rule: {rule['title']}")
        print(
            f"Threshold: >= {rule['threshold']} failures / {rule['timeframe_seconds']} seconds "
            f"grouped by source IP\n"
        )
        for case_id, spec in test_cases.items():
            expected = bool(spec["expected_alert"])
            actual = case_id in alerted_cases
            status = "PASS" if actual == expected else "FAIL"
            print(f"{status:4} {case_id:36} expected_alert={str(expected):5} actual_alert={str(actual):5}")

        print("\nObserved alerts:")
        if not alerts:
            print("  None")
        for alert in alerts:
            print(
                f"  {alert['test_case']}: IP={alert['source_ip']}, "
                f"failures={alert['failure_count']}, users={alert['user_count']}, "
                f"window={alert['window_start']}..{alert['window_end']}"
            )

        failures = [
            case_id
            for case_id, spec in test_cases.items()
            if (case_id in alerted_cases) != bool(spec["expected_alert"])
        ]
        print(f"\nSummary: {len(test_cases) - len(failures)}/{len(test_cases)} test cases passed.")
        if failures:
            print("Mismatches: " + ", ".join(failures), file=sys.stderr)
            return 1
        return 0
    except (OSError, json.JSONDecodeError, csv.Error, KeyError, TypeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
