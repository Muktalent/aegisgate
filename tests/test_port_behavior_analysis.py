import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest


sys.path.append(
    str(Path(__file__).resolve().parents[1] / "backend")
)

from behavior_analysis import analyze_port_diversity


END = datetime(2026, 10, 12, 20, 5, tzinfo=UTC)


def make_event(
    event_id,
    port,
    destination="198.51.100.1",
    timestamp="2026-10-12T20:02:00Z",
    source="10.10.10.99",
):
    return {
        "event_id": event_id,
        "telemetry": {
            "source_ip": source,
            "destination_ip": destination,
            "destination_port": port,
            "timestamp": timestamp,
        },
    }


def analyze(events, **kwargs):
    params = {
        "source_ip": "10.10.10.99",
        "window_end": END,
        "window_minutes": 5,
        "port_threshold": 3,
    }
    params.update(kwargs)

    return analyze_port_diversity(events, **params)


def test_threshold_reached_with_evidence():
    events = [
        make_event("e1", 22),
        make_event("e2", 80),
        make_event("e3", 443),
    ]

    result = analyze(events)

    assert result["triggered"] is True
    assert result["unique_port_count"] == 3
    assert result["observed_ports"] == [22, 80, 443]
    assert result["evidence_event_ids"] == ["e1", "e2", "e3"]


def test_repeated_port_does_not_inflate_diversity():
    events = [
        make_event("e1", 443),
        make_event("e2", 443),
    ]

    result = analyze(events)

    assert result["triggered"] is False
    assert result["unique_port_count"] == 1
    assert result["matching_record_count"] == 2


def test_same_port_across_destinations_is_counted_once():
    events = [
        make_event("e1", 443, destination="198.51.100.1"),
        make_event("e2", 443, destination="198.51.100.2"),
    ]

    result = analyze(events)

    assert result["unique_port_count"] == 1
    assert result["ports_by_destination"] == {
        "198.51.100.1": [443],
        "198.51.100.2": [443],
    }


def test_destination_filter():
    events = [
        make_event("e1", 22, destination="198.51.100.1"),
        make_event("e2", 443, destination="198.51.100.2"),
    ]

    result = analyze(events, destination_ip="198.51.100.1")

    assert result["observed_ports"] == [22]
    assert result["evidence_event_ids"] == ["e1"]
    assert result["destination_filter"] == "198.51.100.1"


def test_excludes_other_sources_old_and_future_events():
    events = [
        make_event("old", 22, timestamp="2026-10-12T19:59:59Z"),
        make_event("future", 80, timestamp="2026-10-12T20:05:01Z"),
        make_event("other", 443, source="10.10.10.10"),
    ]

    result = analyze(events)

    assert result["unique_port_count"] == 0
    assert result["evidence_event_ids"] == []


def test_includes_window_boundaries():
    events = [
        make_event("start", 22, timestamp="2026-10-12T20:00:00Z"),
        make_event("end", 443, timestamp="2026-10-12T20:05:00Z"),
    ]

    assert analyze(events)["unique_port_count"] == 2


@pytest.mark.parametrize("port", [None, 0, 65536, True, "443", 443.5])
def test_invalid_port_is_skipped_and_reported(port):
    result = analyze([make_event("invalid", port)])

    assert result["skipped_invalid_ports"] == 1
    assert result["unique_port_count"] == 0
    assert result["evidence_event_ids"] == []


def test_invalid_timestamp_is_reported():
    result = analyze([
        make_event("invalid", 443, timestamp="invalid"),
    ])

    assert result["skipped_invalid_timestamps"] == 1
    assert result["unique_port_count"] == 0


def test_empty_input():
    result = analyze([])

    assert result["triggered"] is False
    assert result["evidence_event_ids"] == []


@pytest.mark.parametrize(
    "changes",
    [
        {"window_end": datetime(2026, 10, 12, 20, 5)},
        {"window_minutes": 0},
        {"port_threshold": 1},
    ],
)
def test_invalid_parameters_are_rejected(changes):
    with pytest.raises(ValueError):
        analyze([], **changes)