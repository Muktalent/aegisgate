import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest


sys.path.append(
    str(Path(__file__).resolve().parents[1] / "backend")
)

from behavior_analysis import analyze_destination_diversity


END = datetime(2026, 10, 12, 20, 5, tzinfo=UTC)


def make_event(event_id, destination, timestamp, source="10.10.10.99"):
    return {
        "event_id": event_id,
        "telemetry": {
            "source_ip": source,
            "destination_ip": destination,
            "timestamp": timestamp,
        },
    }


def analyze(events, **kwargs):
    return analyze_destination_diversity(
        events,
        source_ip="10.10.10.99",
        window_end=END,
        destination_threshold=3,
        **kwargs,
    )


def test_threshold_reached_with_evidence():
    events = [
        make_event("e1", "198.51.100.1", "2026-10-12T20:01:00Z"),
        make_event("e2", "198.51.100.2", "2026-10-12T20:02:00Z"),
        make_event("e3", "198.51.100.3", "2026-10-12T20:03:00Z"),
    ]

    result = analyze(events)

    assert result["triggered"] is True
    assert result["unique_destination_count"] == 3
    assert result["evidence_event_ids"] == ["e1", "e2", "e3"]


def test_repeated_destination_does_not_inflate_diversity():
    events = [
        make_event("e1", "198.51.100.1", "2026-10-12T20:01:00Z"),
        make_event("e2", "198.51.100.1", "2026-10-12T20:02:00Z"),
    ]

    result = analyze(events)

    assert result["triggered"] is False
    assert result["unique_destination_count"] == 1
    assert result["matching_record_count"] == 2


def test_excludes_other_sources_old_and_future_events():
    events = [
        make_event("old", "198.51.100.1", "2026-10-12T19:59:59Z"),
        make_event("future", "198.51.100.2", "2026-10-12T20:05:01Z"),
        make_event(
            "other",
            "198.51.100.3",
            "2026-10-12T20:02:00Z",
            source="10.10.10.10",
        ),
    ]

    result = analyze(events)

    assert result["unique_destination_count"] == 0
    assert result["evidence_event_ids"] == []


def test_includes_window_boundaries():
    events = [
        make_event("start", "198.51.100.1", "2026-10-12T20:00:00Z"),
        make_event("end", "198.51.100.2", "2026-10-12T20:05:00Z"),
    ]

    assert analyze(events)["unique_destination_count"] == 2


def test_invalid_timestamp_is_reported():
    events = [
        make_event("bad", "198.51.100.1", "invalid"),
    ]

    result = analyze(events)

    assert result["skipped_invalid_timestamps"] == 1
    assert result["unique_destination_count"] == 0


def test_empty_input():
    result = analyze([])

    assert result["triggered"] is False
    assert result["evidence_event_ids"] == []


def test_naive_window_end_is_rejected():
    with pytest.raises(ValueError):
        analyze_destination_diversity(
            [],
            source_ip="10.10.10.99",
            window_end=datetime(2026, 10, 12, 20, 5),
        )