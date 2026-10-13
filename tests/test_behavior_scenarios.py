import sys
from pathlib import Path

import pytest


sys.path.append(
    str(Path(__file__).resolve().parents[1] / "backend")
)

from behavior_analysis import analyze_network_behavior
from behavior_scenarios import (
    SCENARIO_NAMES,
    build_behavior_scenario,
)
from telemetry_adapters import (
    normalize_network_telemetry,
    parse_timestamp,
)


@pytest.mark.parametrize("scenario", SCENARIO_NAMES)
def test_scenario_normalizes_and_matches_expected_summary(scenario):
    fixture = build_behavior_scenario(scenario)

    events = [
        {
            "event_id": f"synthetic-{scenario}-{index}",
            "telemetry": normalize_network_telemetry(
                raw_event
            ).model_dump(
                mode="json",
                exclude={"raw_event"},
            ),
        }
        for index, raw_event in enumerate(fixture["raw_events"])
    ]

    result = analyze_network_behavior(
        events,
        source_ip=fixture["source_ip"],
        window_end=parse_timestamp(fixture["window_end"]),
        window_minutes=fixture["window_minutes"],
        destination_threshold=fixture["destination_threshold"],
        port_threshold=fixture["port_threshold"],
    )

    expected = fixture["expected"]
    destinations = result["destination_analysis"]
    ports = result["port_analysis"]

    assert result["pattern"] == expected["pattern"]
    assert result["triggered"] is (
        scenario != "neither_threshold_reached"
    )

    assert destinations["unique_destination_count"] == (
        expected["unique_destination_count"]
    )
    assert ports["unique_port_count"] == expected["unique_port_count"]

    assert destinations["matching_record_count"] == 3
    assert ports["matching_record_count"] == 3
    assert destinations["skipped_invalid_timestamps"] == 0
    assert ports["skipped_invalid_timestamps"] == 0
    assert ports["skipped_invalid_ports"] == 0

    assert len(result["evidence_event_ids"]) == 3
    assert result["shared_evidence_event_ids"] == (
        result["evidence_event_ids"]
    )
    assert result["destination_only_evidence_event_ids"] == []
    assert result["port_only_evidence_event_ids"] == []


@pytest.mark.parametrize("scenario", SCENARIO_NAMES)
def test_scenario_is_reproducible_and_marked_synthetic(scenario):
    first = build_behavior_scenario(scenario)
    second = build_behavior_scenario(scenario)

    assert first == second
    assert first["synthetic"] is True

    for index, raw_event in enumerate(first["raw_events"], start=1):
        assert raw_event["aegisgate_lab"] == {
            "synthetic": True,
            "scenario": scenario,
            "sequence": index,
            "run_id": first["run_id"],
        }


def test_custom_source_and_window():
    fixture = build_behavior_scenario(
        "both_thresholds_reached",
        source_ip="10.10.10.98",
        window_end="2026-10-13T15:05:00+02:00",
    )

    assert fixture["source_ip"] == "10.10.10.98"
    assert fixture["window_start"] == "2026-10-13T13:00:00+00:00"
    assert fixture["window_end"] == "2026-10-13T13:05:00+00:00"

    for raw_event in fixture["raw_events"]:
        assert raw_event["src_ip"] == "10.10.10.98"

        timestamp = parse_timestamp(raw_event["timestamp"])
        assert (
            parse_timestamp(fixture["window_start"])
            <= timestamp
            <= parse_timestamp(fixture["window_end"])
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"scenario": "unsupported"},
        {"source_ip": ""},
        {"window_end": "invalid"},
        {"window_end": "2026-10-13T12:05:00"},
    ],
)
def test_invalid_scenario_parameters(changes):
    params = {"scenario": "both_thresholds_reached"}
    params.update(changes)

    with pytest.raises(ValueError):
        build_behavior_scenario(**params)


def test_explicit_run_id_is_preserved_after_normalization():
    fixture = build_behavior_scenario(
        "both_thresholds_reached",
        run_id="demo-run-001",
    )

    assert fixture["run_id"] == "demo-run-001"

    for raw_event in fixture["raw_events"]:
        telemetry = normalize_network_telemetry(raw_event)

        assert telemetry.lab_metadata is not None
        assert telemetry.lab_metadata.run_id == "demo-run-001"


def test_different_runs_keep_the_same_observations():
    first = build_behavior_scenario(
        "both_thresholds_reached",
        run_id="demo-run-001",
    )
    second = build_behavior_scenario(
        "both_thresholds_reached",
        run_id="demo-run-002",
    )

    assert first["run_id"] != second["run_id"]
    assert first["expected"] == second["expected"]

    for first_event, second_event in zip(
        first["raw_events"],
        second["raw_events"],
        strict=True,
    ):
        assert first_event["aegisgate_lab"]["run_id"] != (
            second_event["aegisgate_lab"]["run_id"]
        )

        first_observation = {
            key: value
            for key, value in first_event.items()
            if key != "aegisgate_lab"
        }
        second_observation = {
            key: value
            for key, value in second_event.items()
            if key != "aegisgate_lab"
        }

        assert first_observation == second_observation


@pytest.mark.parametrize(
    "run_id",
    [
        None,
        "",
        " ",
        "run with spaces",
        "../run",
        "x" * 101,
    ],
)
def test_invalid_run_id_is_rejected(run_id):
    with pytest.raises(ValueError):
        build_behavior_scenario(
            "both_thresholds_reached",
            run_id=run_id,
        )
