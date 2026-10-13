import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest


sys.path.append(
    str(Path(__file__).resolve().parents[1] / "backend")
)

from behavior_analysis import analyze_network_behavior


END = datetime(2026, 10, 12, 20, 5, tzinfo=UTC)


def make_event(event_id, destination, port):
    return {
        "event_id": event_id,
        "telemetry": {
            "source_ip": "10.10.10.99",
            "destination_ip": destination,
            "destination_port": port,
            "timestamp": "2026-10-12T20:02:00Z",
        },
    }


def analyze(events, **changes):
    params = {
        "source_ip": "10.10.10.99",
        "window_end": END,
        "window_minutes": 5,
        "destination_threshold": 2,
        "port_threshold": 2,
    }
    params.update(changes)

    return analyze_network_behavior(events, **params)


@pytest.mark.parametrize(
    "observations, expected_pattern, expected_triggered",
    [
        (
            [("198.51.100.1", 443)],
            "neither_threshold_reached",
            False,
        ),
        (
            [("198.51.100.1", 443), ("198.51.100.2", 443)],
            "destination_threshold_only",
            True,
        ),
        (
            [("198.51.100.1", 22), ("198.51.100.1", 443)],
            "port_threshold_only",
            True,
        ),
        (
            [("198.51.100.1", 22), ("198.51.100.2", 443)],
            "both_thresholds_reached",
            True,
        ),
    ],
)
def test_four_threshold_patterns(
    observations,
    expected_pattern,
    expected_triggered,
):
    events = [
        make_event(f"e{index}", destination, port)
        for index, (destination, port) in enumerate(observations)
    ]

    result = analyze(events)

    assert result["pattern"] == expected_pattern
    assert result["triggered"] is expected_triggered
    assert result["analysis_type"] == "network_behavior_summary"

    assert result["destination_analysis"]["window_start"] == (
        result["port_analysis"]["window_start"]
    )
    assert result["destination_analysis"]["window_end"] == (
        result["port_analysis"]["window_end"]
    )


def test_evidence_sets_and_missing_port_are_preserved():
    events = [
        make_event("e1", "198.51.100.1", 443),
        make_event("e2", "198.51.100.2", None),
    ]

    result = analyze(events)

    assert result["pattern"] == "destination_threshold_only"
    assert result["evidence_event_ids"] == ["e1", "e2"]
    assert result["shared_evidence_event_ids"] == ["e1"]
    assert result["destination_only_evidence_event_ids"] == ["e2"]
    assert result["port_only_evidence_event_ids"] == []

    destinations = result["destination_analysis"]
    ports = result["port_analysis"]

    assert destinations["unique_destination_count"] == 2
    assert destinations["matching_record_count"] == 2

    assert ports["unique_port_count"] == 1
    assert ports["matching_record_count"] == 1
    assert ports["skipped_invalid_ports"] == 1


def test_empty_history():
    result = analyze([])

    assert result["pattern"] == "neither_threshold_reached"
    assert result["triggered"] is False
    assert result["evidence_event_ids"] == []
    assert result["shared_evidence_event_ids"] == []
    assert result["destination_only_evidence_event_ids"] == []
    assert result["port_only_evidence_event_ids"] == []


@pytest.mark.parametrize(
    "changes",
    [
        {"window_end": datetime(2026, 10, 12, 20, 5)},
        {"window_minutes": 0},
        {"destination_threshold": 1},
        {"port_threshold": 1},
    ],
)
def test_invalid_parameters(changes):
    with pytest.raises(ValueError):
        analyze([], **changes)