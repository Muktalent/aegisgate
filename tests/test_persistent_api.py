import sys
from pathlib import Path

from fastapi.testclient import TestClient


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"

sys.path.append(str(BACKEND_DIR))

from app.main import app
from security import create_access_token


client = TestClient(app)


def authorization_header(
    username: str,
    role: str,
) -> dict[str, str]:
    token = create_access_token(
        username=username,
        role=role,
    )

    return {
        "Authorization": f"Bearer {token}",
    }


def simulate_event(
    scenario: str,
) -> dict:
    response = client.post(
        "/v1/simulation/events",
        headers=authorization_header(
            "test-ingestor",
            "ingestor",
        ),
        json={
            "scenario": scenario,
        },
    )

    assert response.status_code == 200

    return response.json()


def test_persistent_api_health_endpoint_is_public() -> None:
    response = client.get("/health")

    assert response.status_code == 200

    assert response.json() == {
        "status": "ok",
        "service": "aegisgate-api",
        "version": "0.1.0",
    }


def test_simulation_requires_bearer_authentication() -> None:
    response = client.post(
        "/v1/simulation/events",
        json={
            "scenario": "suricata_c2",
        },
    )

    assert response.status_code == 401

    assert response.json() == {
        "detail": "Bearer authentication is required."
    }


def test_ingestor_can_simulate_and_persist_suricata_event() -> None:
    created = simulate_event("suricata_c2")

    assert created["event_id"]
    assert created["status"] == "processed"
    assert created["telemetry"]["source"] == "suricata"
    assert created["telemetry"]["source_ip"] == "10.10.10.50"
    assert created["risk_assessment"]["score"] == 100
    assert created["access_decision"]["action"] == "deny"

    events_response = client.get(
        "/v1/events",
        headers=authorization_header(
            "test-soc-analyst",
            "soc_analyst",
        ),
    )

    assert events_response.status_code == 200

    event_ids = {
        event["event_id"]
        for event in events_response.json()
    }

    assert created["event_id"] in event_ids


def test_soc_analyst_cannot_simulate_event() -> None:
    response = client.post(
        "/v1/simulation/events",
        headers=authorization_header(
            "test-soc-analyst",
            "soc_analyst",
        ),
        json={
            "scenario": "zeek_dns_c2",
        },
    )

    assert response.status_code == 403

    assert response.json() == {
        "detail": "Your role is not authorised for this operation."
    }


def test_unknown_asset_is_persisted_for_manual_review() -> None:
    created = simulate_event("unknown_asset")

    assert created["event_id"]
    assert created["status"] == "unresolved_asset"
    assert created["connection_event"] is None
    assert created["risk_assessment"] is None
    assert created["access_decision"]["action"] == "manual_review"
    assert created["error"] == (
        "No asset inventory record found for 10.10.10.99."
    )


def test_invalid_simulation_scenario_is_rejected() -> None:
    response = client.post(
        "/v1/simulation/events",
        headers=authorization_header(
            "test-ingestor",
            "ingestor",
        ),
        json={
            "scenario": "unsupported_scenario",
        },
    )

    assert response.status_code == 422
    assert "Unsupported scenario" in response.json()["detail"]


def test_soc_analyst_can_investigate_persisted_ip() -> None:
    simulate_event("zeek_dns_c2")

    investigation_response = client.get(
        "/v1/investigations/ip/10.10.10.25",
        headers=authorization_header(
            "test-soc-analyst",
            "soc_analyst",
        ),
    )

    assert investigation_response.status_code == 200

    investigation = investigation_response.json()

    assert investigation["indicator"] == "10.10.10.25"
    assert investigation["indicator_type"] == "ip"
    assert investigation["alert_count"] >= 1
    assert "LAB-WS-001" in investigation["affected_assets"]
    assert investigation["note"].startswith(
        "This result uses persisted local AegisGate evidence only."
    )


def test_ingestor_cannot_list_persisted_events() -> None:
    response = client.get(
        "/v1/events",
        headers=authorization_header(
            "test-ingestor",
            "ingestor",
        ),
    )

    assert response.status_code == 403

    assert response.json() == {
        "detail": "Your role is not authorised for this operation."
    }


def test_soc_analyst_can_create_case_for_persisted_alert() -> None:
    event = simulate_event("suricata_c2")

    case_response = client.post(
        f"/v1/events/{event['event_id']}/case",
        headers=authorization_header(
            "test-soc-analyst",
            "soc_analyst",
        ),
        json={
            "title": "Investigate suspected C2 on finance device",
            "analyst_note": "Case opened from the SOC laboratory queue.",
        },
    )

    assert case_response.status_code == 200

    incident_case = case_response.json()

    assert incident_case["case_id"]
    assert incident_case["alert_event_id"] == event["event_id"]
    assert incident_case["status"] == "open"
    assert incident_case["created_by"] == "test-soc-analyst"
    assert incident_case["updated_by"] == "test-soc-analyst"


def test_case_cannot_be_created_twice_for_same_alert() -> None:
    event = simulate_event("zeek_notice_c2")

    headers = authorization_header(
        "test-soc-analyst",
        "soc_analyst",
    )

    first_case_response = client.post(
        f"/v1/events/{event['event_id']}/case",
        headers=headers,
        json={
            "title": "Investigate Zeek notice",
        },
    )

    assert first_case_response.status_code == 200

    second_case_response = client.post(
        f"/v1/events/{event['event_id']}/case",
        headers=headers,
        json={
            "title": "Duplicate case attempt",
        },
    )

    assert second_case_response.status_code == 409

    assert second_case_response.json() == {
        "detail": (
            "A case already exists for "
            f"event_id '{event['event_id']}'."
        )
    }


def test_soc_analyst_can_update_case_to_resolved() -> None:
    event = simulate_event("zeek_dns_c2")

    headers = authorization_header(
        "test-soc-analyst",
        "soc_analyst",
    )

    case_response = client.post(
        f"/v1/events/{event['event_id']}/case",
        headers=headers,
        json={
            "title": "Review suspicious DNS activity",
        },
    )

    assert case_response.status_code == 200

    case_id = case_response.json()["case_id"]

    update_response = client.patch(
        f"/v1/cases/{case_id}",
        headers=headers,
        json={
            "status": "resolved",
            "analyst_note": (
                "Device was reviewed and the security team completed "
                "the laboratory response."
            ),
        },
    )

    assert update_response.status_code == 200

    updated_case = update_response.json()

    assert updated_case["case_id"] == case_id
    assert updated_case["status"] == "resolved"
    assert updated_case["updated_by"] == "test-soc-analyst"
    assert updated_case["analyst_note"].startswith(
        "Device was reviewed"
    )


def test_ingestor_cannot_create_or_update_cases() -> None:
    event = simulate_event("suricata_c2")

    response = client.post(
        f"/v1/events/{event['event_id']}/case",
        headers=authorization_header(
            "test-ingestor",
            "ingestor",
        ),
        json={
            "title": "Unauthorized case creation attempt",
        },
    )

    assert response.status_code == 403

    assert response.json() == {
        "detail": "Your role is not authorised for this operation."
    }

    def test_soc_analyst_can_view_dashboard_summary() -> None:
        simulate_event("suricata_c2")
        simulate_event("zeek_dns_c2")
        simulate_event("unknown_asset")

    response = client.get(
        "/v1/dashboard/summary",
        headers=authorization_header(
            "test-soc-analyst",
            "soc_analyst",
        ),
    )

    assert response.status_code == 200

    summary = response.json()

    assert summary["total_alerts"] >= 3
    assert summary["critical_alerts"] >= 1
    assert summary["denied_events"] >= 1
    assert summary["unresolved_assets"] >= 1
    assert summary["alerts_by_source"]["suricata"] >= 1
    assert summary["alerts_by_source"]["zeek"] >= 1

    assert set(summary["cases_by_status"]) == {
        "open",
        "acknowledged",
        "resolved",
        "false_positive",
    }


def test_dashboard_summary_counts_open_cases() -> None:
    event = simulate_event("zeek_notice_c2")

    create_case_response = client.post(
        f"/v1/events/{event['event_id']}/case",
        headers=authorization_header(
            "test-soc-analyst",
            "soc_analyst",
        ),
        json={
            "title": "Dashboard case-count validation",
        },
    )

    assert create_case_response.status_code == 200

    response = client.get(
        "/v1/dashboard/summary",
        headers=authorization_header(
            "test-soc-analyst",
            "soc_analyst",
        ),
    )

    assert response.status_code == 200
    assert response.json()["open_cases"] >= 1
    assert response.json()["cases_by_status"]["open"] >= 1


def test_ingestor_cannot_view_dashboard_summary() -> None:
    response = client.get(
        "/v1/dashboard/summary",
        headers=authorization_header(
            "test-ingestor",
            "ingestor",
        ),
    )

    assert response.status_code == 403

    assert response.json() == {
        "detail": "Your role is not authorised for this operation."
    }