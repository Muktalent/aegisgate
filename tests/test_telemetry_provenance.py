import sys
from pathlib import Path

import pytest
from pydantic import ValidationError


sys.path.append(
    str(Path(__file__).resolve().parents[1] / "backend")
)

from behavior_scenarios import build_behavior_scenario
from telemetry_adapters import normalize_network_telemetry
from telemetry_pipeline import process_network_event


def scenario_event():
    fixture = build_behavior_scenario("both_thresholds_reached")
    return fixture["raw_events"][0]


@pytest.mark.parametrize("source_ip", ["10.10.10.99", "10.10.10.50"])
def test_pipeline_preserves_lab_metadata_without_raw_event(source_ip):
    raw_event = scenario_event()
    raw_event["src_ip"] = source_ip

    result = process_network_event(raw_event)
    telemetry = result["telemetry"]

    assert telemetry["lab_metadata"] == raw_event["aegisgate_lab"]
    assert "raw_event" not in telemetry

    if source_ip == "10.10.10.99":
        assert result["status"] == "unresolved_asset"
        assert result["access_decision"]["action"] == "manual_review"
    else:
        assert result["status"] == "processed"
        assert "risk_assessment" in result

    unmarked_event = dict(raw_event)
    unmarked_event.pop("aegisgate_lab")

    unmarked_result = process_network_event(unmarked_event)

    assert result["status"] == unmarked_result["status"]
    assert result["access_decision"] == unmarked_result["access_decision"]
    assert result.get("risk_assessment") == (
        unmarked_result.get("risk_assessment")
    )


def test_unmarked_event_has_no_declared_lab_metadata():
    raw_event = scenario_event()
    raw_event.pop("aegisgate_lab")

    telemetry = normalize_network_telemetry(raw_event)

    assert telemetry.lab_metadata is None


def test_zeek_adapter_preserves_lab_metadata():
    metadata = {
        "synthetic": True,
        "scenario": "zeek_metadata_test",
        "sequence": 1,
        "run_id": "zeek-test-001",
    }

    raw_event = {
        "_zeek_log_type": "connection",
        "ts": 1791892920,
        "id.orig_h": "10.10.10.99",
        "id.resp_h": "198.51.100.1",
        "id.resp_p": 443,
        "proto": "tcp",
        "aegisgate_lab": metadata,
    }

    telemetry = normalize_network_telemetry(raw_event)

    assert telemetry.source == "zeek"
    assert telemetry.lab_metadata is not None
    assert telemetry.lab_metadata.model_dump() == metadata


@pytest.mark.parametrize(
    "changes",
    [
        {"synthetic": "true"},
        {"sequence": True},
        {"sequence": 0},
        {"scenario": ""},
    ],
)
def test_invalid_lab_metadata_is_rejected(changes):
    raw_event = scenario_event()
    raw_event["aegisgate_lab"] = {
        **raw_event["aegisgate_lab"],
        **changes,
    }

    with pytest.raises(ValidationError):
        normalize_network_telemetry(raw_event)