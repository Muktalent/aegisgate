"""Each Demo Lab scenario must produce its expected outcome through the real
analysis pipeline. Nothing here is precomputed."""
from datetime import datetime, timezone

import pytest

import core_helpers  # noqa: F401
from app.core import scenarios
from app.core.events import event_from_stored_telemetry
from app.core.pipeline import analyse
from app.core.risk import AssetContext

START = datetime(2026, 11, 16, 9, 0, 0, tzinfo=timezone.utc)
INVENTORY = {scenarios.WORKSTATION: AssetContext("lab-workstation-001", True, "high"),
             scenarios.FINANCE: AssetContext("lab-finance-001", True, "critical")}


def stored(raw, index):
    """What the ingestion adapter keeps for a Suricata event (see telemetry_adapters.py)."""
    alert, flow = raw.get("alert", {}), raw.get("flow", {})
    return event_from_stored_telemetry(f"{raw['aegisgate_lab']['run_id']}-{index}", {
        "source": "suricata", "event_type": raw["event_type"], "timestamp": raw["timestamp"],
        "source_ip": raw["src_ip"], "destination_ip": raw["dest_ip"], "destination_port": raw["dest_port"],
        "protocol": raw["proto"], "severity": alert.get("severity", 3), "signature": alert.get("signature"),
        "signature_id": alert.get("signature_id"), "category": alert.get("category"),
        "bytes_out": flow.get("bytes_toserver"), "bytes_in": flow.get("bytes_toclient"),
        "lab_metadata": raw["aegisgate_lab"]})


def run(scenario_id):
    baseline, events = scenarios.build(scenario_id, "run-1", START)
    result = analyse([stored(e, i) for i, e in enumerate(events)], INVENTORY,
                     [stored(e, i) for i, e in enumerate(baseline)])
    return baseline, events, result


@pytest.mark.parametrize("scenario_id", sorted(scenarios.SCENARIOS))
def test_scenario_produces_its_expected_outcome(scenario_id):
    _, events, result = run(scenario_id)
    assert events, "a scenario must generate events"
    assert len(result.findings) <= 1
    finding = result.findings[0] if result.findings else None
    outcome = scenarios.compare(
        scenario_id, [d.rule_id for d in result.detections],
        finding.group.finding if finding else None, finding.decision.decision if finding else None)
    assert outcome["matches_expected"], outcome


def test_scenarios_are_deterministic_and_tagged():
    first = scenarios.build("multi_stage", "run-1", START)
    assert first == scenarios.build("multi_stage", "run-1", START)
    baseline, events = first
    assert {e["aegisgate_lab"]["run_id"] for e in events} == {"run-1"}
    assert {e["aegisgate_lab"]["run_id"] for e in baseline} == {"run-1.baseline"}
    assert all(e["aegisgate_lab"]["synthetic"] is True for e in baseline + events)
    assert [e["aegisgate_lab"]["sequence"] for e in events] == list(range(1, len(events) + 1))
    assert max(e["timestamp"] for e in baseline) < min(e["timestamp"] for e in events)


def test_benign_and_malicious_scenarios_are_both_present():
    truths = [s.ground_truth for s in scenarios.SCENARIOS.values()]
    assert truths.count("benign") >= 2 and truths.count("malicious") >= 5
    assert len(scenarios.SCENARIOS) == 8
    for scenario in scenarios.SCENARIOS.values():
        info = scenario.describe()
        assert info["title"] and info["description"] and info["ground_truth"] in ("benign", "malicious")


def test_benign_lookalike_fires_but_is_not_restricted():
    _, _, result = run("benign_backup")
    (finding,) = result.findings
    assert finding.decision.decision not in ("step_up_authentication", "deny")
    assert finding.decision.recommended_actions == ("flag_for_investigation",)
    assert "false positive" in scenarios.SCENARIOS["benign_backup"].notes


def test_unknown_device_never_gets_an_automatic_restriction():
    _, _, result = run("unknown_device")
    (finding,) = result.findings
    assert not finding.assessment.asset_identified and finding.decision.decision == "manual_review"


def test_invalid_scenario_or_start():
    with pytest.raises(ValueError):
        scenarios.build("no_such_scenario", "r", START)
    with pytest.raises(ValueError):
        scenarios.build("port_scan", "r", START.replace(tzinfo=None))


def test_rules_firing_on_the_same_flows_are_not_double_counted():
    _, _, result = run("potential_exfiltration")
    (finding,) = result.findings
    assert {d.rule_id for d in result.detections} == {"DET-003", "DET-004"}
    assert finding.assessment.corroborating_categories == 1
    overlap = [f for f in finding.assessment.factors if f.factor.startswith("overlapping_evidence_")]
    assert len(overlap) == 1 and overlap[0].contribution == 0
    assert finding.decision.decision != "deny"
