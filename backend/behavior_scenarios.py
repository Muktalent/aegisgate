import re
from datetime import timedelta
from typing import Any

from telemetry_adapters import parse_timestamp


SCENARIO_NAMES = (
    "neither_threshold_reached",
    "destination_threshold_only",
    "port_threshold_only",
    "both_thresholds_reached",
)

DEFAULT_WINDOW_END = "2026-10-13T12:05:00Z"
DEFAULT_SOURCE_IP = "10.10.10.99"
DEFAULT_RUN_ID = "fixture-run"


def build_behavior_scenario(
    scenario: str,
    *,
    source_ip: str = DEFAULT_SOURCE_IP,
    window_end: str = DEFAULT_WINDOW_END,
    run_id: str = DEFAULT_RUN_ID,
) -> dict[str, Any]:
    if scenario not in SCENARIO_NAMES:
        raise ValueError(f"Unsupported behavior scenario: {scenario}")

    if not isinstance(source_ip, str) or not source_ip.strip():
        raise ValueError("source_ip must be a non-empty string.")

    if (
        not isinstance(run_id, str)
        or not 1 <= len(run_id) <= 100
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", run_id) is None
    ):
        raise ValueError(
            "run_id must contain 1-100 characters: "
            "letters, digits, dots, underscores, or hyphens, "
            "starting with a letter or digit."
        )

    end = parse_timestamp(window_end)
    start = end - timedelta(minutes=5)

    observations = {
        "neither_threshold_reached": [
            ("198.51.100.1", 443),
            ("198.51.100.1", 443),
            ("198.51.100.1", 443),
        ],
        "destination_threshold_only": [
            ("198.51.100.1", 443),
            ("198.51.100.2", 443),
            ("198.51.100.3", 443),
        ],
        "port_threshold_only": [
            ("198.51.100.1", 22),
            ("198.51.100.1", 80),
            ("198.51.100.1", 443),
        ],
        "both_thresholds_reached": [
            ("198.51.100.1", 22),
            ("198.51.100.2", 80),
            ("198.51.100.3", 443),
        ],
    }

    raw_events = [
        {
            "event_type": "flow",
            "timestamp": (
                start + timedelta(minutes=index + 1)
            ).isoformat(),
            "src_ip": source_ip.strip(),
            "dest_ip": destination,
            "dest_port": port,
            "proto": "TCP",
            "aegisgate_lab": {
                "synthetic": True,
                "scenario": scenario,
                "sequence": index + 1,
                "run_id": run_id,
            },
        }
        for index, (destination, port) in enumerate(
            observations[scenario]
        )
    ]

    return {
        "scenario": scenario,
        "synthetic": True,
        "run_id": run_id,
        "source_ip": source_ip.strip(),
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "window_minutes": 5,
        "destination_threshold": 3,
        "port_threshold": 3,
        "expected": {
            "pattern": scenario,
            "unique_destination_count": (
                3
                if scenario in (
                    "destination_threshold_only",
                    "both_thresholds_reached",
                )
                else 1
            ),
            "unique_port_count": (
                3
                if scenario in (
                    "port_threshold_only",
                    "both_thresholds_reached",
                )
                else 1
            ),
            "matching_record_count": 3,
        },
        "raw_events": raw_events,
    }