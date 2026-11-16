import pytest

from core_helpers import T0, beacon, ev, host_sweep, ids_alert, office_traffic, port_scan, upload
from app.core.detection import (DestinationScanRule, DetectionEngine, IdsAlertRule,
                                PortScanRule, PotentialExfiltrationRule, SuspiciousOutboundRule)
from app.core.events import CanonicalEvent, event_from_stored_telemetry, is_internal_address, parse_utc


def test_port_scan_detected_with_evidence_and_explanation():
    events = port_scan(20)
    (d,) = PortScanRule().evaluate(events)
    assert d.rule_id == "DET-001" and d.category == "port_scan" and d.severity == "medium"
    assert d.observations["distinct_port_count"] == 20
    assert set(d.supporting_events) == {e.event_id for e in events}
    assert 0.6 <= d.confidence <= 0.9 and "20 distinct destination ports" in d.explanation


def test_port_scan_below_threshold_and_repeated_port_not_detected():
    assert PortScanRule().evaluate(port_scan(14)) == []
    assert PortScanRule().evaluate([ev(i, port=443) for i in range(200)]) == []


def test_port_scan_outside_window_not_detected():
    assert PortScanRule().evaluate(port_scan(20, step=10.0)) == []     # 20 ports over 190 s


def test_port_scan_threshold_is_configurable_and_severity_scales():
    assert len(PortScanRule(threshold=5).evaluate(port_scan(6))) == 1
    (d,) = PortScanRule().evaluate(port_scan(50, step=0.5))
    assert d.severity == "high" and d.confidence == 0.9


def test_port_scan_is_per_source_and_order_independent():
    events = port_scan(20, src="10.10.10.25") + port_scan(8, src="10.10.10.50")
    found = PortScanRule().evaluate(list(reversed(events)))
    assert [d.source_ip for d in found] == ["10.10.10.25"]


def test_detection_ids_are_stable_across_runs():
    events = port_scan(20)
    assert PortScanRule().evaluate(events)[0].detection_id == PortScanRule().evaluate(events)[0].detection_id
    twice = DetectionEngine().run(events + events)
    assert len([d for d in twice if d.rule_id == "DET-001"]) == 1


def test_destination_scan():
    (d,) = DestinationScanRule().evaluate(host_sweep(12))
    assert d.rule_id == "DET-002" and d.observations["distinct_destination_count"] == 12
    assert DestinationScanRule().evaluate(host_sweep(9)) == []


def test_regular_external_connections_detected():
    (d,) = SuspiciousOutboundRule().evaluate(beacon(8))
    assert d.rule_id == "DET-003" and d.observations["destination_ip"] == "198.51.100.23"
    assert d.observations["mean_interval_seconds"] == 60.0


def test_irregular_or_internal_or_few_connections_not_flagged():
    irregular = [ev(t, dst="198.51.100.23") for t in (0, 5, 70, 80, 300, 310, 500, 590)]
    assert SuspiciousOutboundRule().evaluate(irregular) == []
    assert SuspiciousOutboundRule().evaluate(beacon(8, dst="10.10.10.9")) == []
    assert SuspiciousOutboundRule().evaluate(beacon(7)) == []


def test_exfiltration_absolute_threshold():
    (d,) = PotentialExfiltrationRule().evaluate(upload(60))
    assert d.rule_id == "DET-004" and "insufficient baseline" in d.observations["threshold_basis"]
    assert any("not proof" in text for text in d.limitations)
    assert PotentialExfiltrationRule().evaluate(upload(20)) == []


def test_exfiltration_uses_baseline_when_available():
    events = upload(20)
    assert len(PotentialExfiltrationRule().evaluate(events, {"10.10.10.50": 1024 * 1024})) == 1
    assert PotentialExfiltrationRule().evaluate(events, {"10.10.10.50": 30 * 1024 * 1024}) == []


def test_exfiltration_ignores_internal_transfers_and_missing_sizes():
    assert PotentialExfiltrationRule().evaluate(upload(200, dst="10.10.10.9")) == []
    assert PotentialExfiltrationRule().evaluate([ev(i, dst="198.51.100.77") for i in range(50)]) == []


def test_ids_alerts_grouped_by_signature_without_claiming_success():
    alerts = [ids_alert(0), ids_alert(5), ids_alert(8, sid=2010935, severity=3, signature="ET SCAN x")]
    found = IdsAlertRule().evaluate(alerts)
    assert sorted((d.observations["alert_count"], d.severity) for d in found) == [(1, "low"), (2, "high")]
    assert all(d.confidence == 0.6 for d in found)
    assert any("does not show that an attack succeeded" in t for t in found[0].limitations)


def test_keywords_in_text_do_not_create_detections():
    noisy = [ev(i, signature="malware trojan c2 ransomware exploit", category="botnet") for i in range(5)]
    assert DetectionEngine().run(noisy) == []


def test_normal_office_traffic_produces_no_detections():
    assert DetectionEngine().run(office_traffic()) == []


def test_perfectly_periodic_benign_traffic_is_a_known_false_positive():
    """Documented limitation of DET-003: an updater polling every minute looks
    the same as a beacon. The rule flags it; risk and policy must temper it."""
    polling = [ev(i * 60, dst="198.51.100.10", bytes_out=300) for i in range(10)]
    (d,) = SuspiciousOutboundRule().evaluate(polling)
    assert d.severity == "medium" and any("updaters" in t for t in d.limitations)


def test_outbound_rule_false_positive_rate_on_irregular_traffic_is_low():
    """Regression guard for the calibration in docs/03-analysis-core.md."""
    flagged = sum(bool(SuspiciousOutboundRule().evaluate(office_traffic(seed=s, minutes=120, start=-7200)))
                  for s in range(100))
    assert flagged <= 2
    assert all(SuspiciousOutboundRule().evaluate(beacon(10, jitter=j)) for j in (0, 3, 6, 9, 12))


def test_every_rule_documents_itself():
    for rule in DetectionEngine().rules:
        info = rule.describe()
        assert info["rule_id"].startswith("DET-") and info["version"] and info["description"]
        assert info["window_seconds"] > 0 and info["input_requirements"]


@pytest.mark.parametrize("value,expected", [
    ("2026-11-15T12:00:00Z", T0), ("2026-11-15T13:00:00+01:00", T0),
    ("2026-11-15T12:00:00.000000+0000", T0), (T0.timestamp(), T0)])
def test_parse_utc(value, expected):
    assert parse_utc(value) == expected


@pytest.mark.parametrize("value", [None, True, "", "yesterday", "2026-11-15T12:00:00", float("inf")])
def test_parse_utc_rejects_invalid(value):
    with pytest.raises(ValueError):
        parse_utc(value)


def test_internal_address_classification():
    assert is_internal_address("10.10.10.25") is True
    assert is_internal_address("198.51.100.23") is False
    assert is_internal_address("not-an-ip") is None and is_internal_address(None) is None


@pytest.mark.parametrize("kw", [{"destination_port": 0}, {"destination_port": 70000},
                                {"bytes_out": -1}, {"source_ip": ""}, {"event_id": ""}])
def test_canonical_event_validation(kw):
    base = dict(event_id="e1", timestamp=T0, source="zeek", event_type="flow", source_ip="10.0.0.1")
    with pytest.raises(ValueError):
        CanonicalEvent(**{**base, **kw})


def test_event_from_stored_prototype_telemetry_keeps_unknowns_unknown():
    stored = {"source": "zeek", "event_type": "dns", "timestamp": "2026-09-27T22:07:10Z",
              "source_ip": "10.10.10.25", "destination_ip": "10.10.10.2", "destination_port": 53,
              "protocol": "udp", "severity": 2, "signature": "Zeek DNS observation",
              "lab_metadata": {"synthetic": True, "scenario": "s1", "sequence": 1, "run_id": "r1"}}
    event = event_from_stored_telemetry("abc", stored)
    assert event.severity is None and event.signature is None and event.bytes_out is None
    assert event.scenario_id == "s1" and event.run_id == "r1" and event.destination_port == 53
