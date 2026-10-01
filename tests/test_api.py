import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


sys.path.append(str(Path(__file__).resolve().parent.parent / "backend"))

import main
from security import create_access_token


@pytest.fixture()
def client(tmp_path, monkeypatch):
    test_audit_file = tmp_path / "audit_log.jsonl"

    monkeypatch.setattr(main, "audit_file", test_audit_file)

    import audit_logger

    monkeypatch.setattr(audit_logger, "audit_file", test_audit_file)

    with TestClient(main.app) as test_client:
        yield test_client


def authorization_header(username: str, role: str) -> dict:
    token = create_access_token(username=username, role=role)

    return {
        "Authorization": f"Bearer {token}",
    }


def infected_event(event_id: str) -> dict:
    return {
        "event_id": event_id,
        "timestamp": "2026-09-27T22:33:00",
        "user_id": "test.user@aegis-demo.local",
        "device_id": "infected-test-device-001",
        "device_name": "Infected-Test-Device",
        "managed_device": True,
        "device_compliant": True,
        "mfa_success": True,
        "location": "Casablanca",
        "known_location": True,
        "usual_hours": True,
        "resource": "finance_data",
        "resource_sensitivity": "critical",
        "requested_action": "export_data",
        "failed_logins_24h": 0,
        "endpoint_health": "infected",
        "infection_signal": True,
    }


def test_access_endpoint_requires_bearer_authentication(client):
    response = client.post(
        "/events/access",
        json=infected_event("test-api-no-token"),
    )

    assert response.status_code == 401
    assert response.json() == {
        "detail": "Bearer authentication is required."
    }


def test_ingestor_can_trigger_containment_and_create_incident(client):
    response = client.post(
        "/events/access",
        headers=authorization_header("test-ingestor", "ingestor"),
        json=infected_event("test-api-containment"),
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["event_id"] == "test-api-containment"
    assert payload["risk_score"] == 100
    assert payload["decision"] == "CONTAINMENT"
    assert payload["audit_recorded"] is True
    assert payload["containment_recorded"] is True
    assert payload["endpoint_status"] == "CONTAINED"
    assert payload["processed_by"] == "test-ingestor"
    assert payload["audit_id"]
    assert payload["correlation_id"]
    assert payload["incident_id"].startswith("INC-")


def test_ingestor_cannot_read_incidents(client):
    response = client.get(
        "/incidents",
        headers=authorization_header("test-ingestor", "ingestor"),
    )

    assert response.status_code == 403
    assert response.json() == {
        "detail": "Your role is not authorised for this operation."
    }


def test_soc_analyst_can_retrieve_created_incident(client):
    create_response = client.post(
        "/events/access",
        headers=authorization_header("test-ingestor", "ingestor"),
        json=infected_event("test-api-incident-lookup"),
    )

    assert create_response.status_code == 200

    incident_id = create_response.json()["incident_id"]

    lookup_response = client.get(
        f"/incidents/{incident_id}",
        headers=authorization_header("test-soc-analyst", "soc_analyst"),
    )

    assert lookup_response.status_code == 200

    incident = lookup_response.json()

    assert incident["incident_id"] == incident_id
    assert incident["event_id"] == "test-api-incident-lookup"
    assert incident["endpoint_status"] == "CONTAINED"
    assert incident["actor_username"] == "test-ingestor"
    assert incident["actor_role"] == "ingestor"
    assert incident["queried_by"] == "test-soc-analyst"


def test_unknown_incident_returns_404_for_soc_analyst(client):
    response = client.get(
        "/incidents/INC-NOT-FOUND",
        headers=authorization_header("test-soc-analyst", "soc_analyst"),
    )

    assert response.status_code == 404
    assert response.json() == {
        "detail": "No containment incident found for incident_id 'INC-NOT-FOUND'."
    }