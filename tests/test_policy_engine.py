import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent / "backend"))

from models import ConnectionEvent
from policy_engine import decide_access
from risk_engine import calculate_risk


def build_event(**overrides) -> ConnectionEvent:
    data = {
        "event_id": "test-event",
        "timestamp": "2026-09-27T10:00:00",
        "user_id": "test.user@aegis-demo.local",
        "device_id": "test-device-001",
        "device_name": "Test-Device",
        "managed_device": True,
        "device_compliant": True,
        "mfa_success": True,
        "location": "Casablanca",
        "known_location": True,
        "usual_hours": True,
        "resource": "crm",
        "resource_sensitivity": "medium",
        "requested_action": "view_customer_records",
        "failed_logins_24h": 0,
        "endpoint_health": "healthy",
        "infection_signal": False,
    }

    data.update(overrides)
    return ConnectionEvent.model_validate(data)


def test_normal_connection_is_allowed():
    event = build_event()

    assessment = calculate_risk(event)
    decision = decide_access(event, assessment)

    assert assessment.score == 5
    assert decision.decision == "ALLOW"
    assert decision.requires_manual_review is False


def test_unknown_device_exporting_finance_data_is_quarantined():
    event = build_event(
        device_id="unknown-device-984",
        device_name="Unknown-Device",
        managed_device=False,
        device_compliant=False,
        known_location=False,
        usual_hours=False,
        resource="finance_data",
        resource_sensitivity="high",
        requested_action="export_data",
        endpoint_health="unknown",
    )

    assessment = calculate_risk(event)
    decision = decide_access(event, assessment)

    assert assessment.score == 100
    assert decision.decision == "QUARANTINE"
    assert decision.allowed_resources == ["quarantine_portal"]
    assert decision.requires_manual_review is True


def test_infection_signal_triggers_containment():
    event = build_event(
        resource="finance_data",
        resource_sensitivity="critical",
        requested_action="export_data",
        endpoint_health="infected",
        infection_signal=True,
    )

    assessment = calculate_risk(event)
    decision = decide_access(event, assessment)

    assert assessment.score == 100
    assert decision.decision == "CONTAINMENT"
    assert decision.allowed_resources == []
    assert decision.requires_manual_review is True


def test_mfa_failure_for_critical_resource_is_blocked():
    event = build_event(
        mfa_success=False,
        resource="finance_data",
        resource_sensitivity="critical",
    )

    assessment = calculate_risk(event)
    decision = decide_access(event, assessment)

    assert decision.decision == "BLOCK"
    assert decision.allowed_resources == []
    assert decision.requires_manual_review is True