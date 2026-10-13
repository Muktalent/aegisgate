import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = PROJECT_ROOT / "backend"

sys.path.append(str(BACKEND_DIR))

import app.main as api
from security import create_access_token


@pytest.fixture(autouse=True)
def isolated_database(tmp_path, monkeypatch):
    database_path = tmp_path / "persistent_api_test.db"

    test_engine = create_engine(
        f"sqlite:///{database_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )

    session_factory = sessionmaker(
        bind=test_engine,
        autoflush=False,
        autocommit=False,
    )

    def override_get_db():
        with session_factory() as session:
            yield session

    previous_overrides = api.app.dependency_overrides.copy()

    monkeypatch.setattr(api, "engine", test_engine)
    api.app.dependency_overrides[api.get_db] = override_get_db

    try:
        with TestClient(api.app) as test_client:
            monkeypatch.setattr(
                sys.modules[__name__],
                "client",
                test_client,
                raising=False,
            )

            yield
    finally:
        api.app.dependency_overrides.clear()
        api.app.dependency_overrides.update(previous_overrides)
        test_engine.dispose()


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

@pytest.mark.parametrize(
    "scenario",
    [
        "suricata_c2",
        "zeek_dns_c2",
        "zeek_notice_c2",
        "unknown_asset",
    ],
)
def test_event_list_preserves_telemetry_display_fields(scenario) -> None:
    created = simulate_event(scenario)

    created_telemetry = created["telemetry"]

    assert created["event_id"]
    assert isinstance(created_telemetry["severity"], int)
    assert not isinstance(created_telemetry["severity"], bool)
    assert created_telemetry["timestamp"]

    response = client.get(
        "/v1/events",
        headers=authorization_header(
            "test-soc-analyst",
            "soc_analyst",
        ),
    )

    assert response.status_code == 200, response.text

    matching_events = [
        event
        for event in response.json()
        if event["event_id"] == created["event_id"]
    ]

    assert len(matching_events) == 1

    listed = matching_events[0]
    listed_telemetry = listed["telemetry"]

    assert listed["event_id"] == created["event_id"]
    assert listed["status"] == created["status"]
    assert listed_telemetry["severity"] == created_telemetry["severity"]
    assert listed_telemetry["timestamp"] == created_telemetry["timestamp"]
    assert listed_telemetry["source"] == created_telemetry["source"]
    assert listed_telemetry["source_ip"] == created_telemetry["source_ip"]

    if scenario == "unknown_asset":
        assert listed["risk_assessment"] is None
        assert listed["status"] == "unresolved_asset"

@pytest.mark.parametrize(
    "source_ip, expected_status",
    [
        ("10.10.10.99", "unresolved_asset"),
        ("10.10.10.50", "processed"),
    ],
)
def test_persistent_api_preserves_declared_lab_metadata(
    source_ip,
    expected_status,
) -> None:
    metadata = {
        "synthetic": True,
        "scenario": "persistence_metadata_test",
        "sequence": 1,
    }

    expected_metadata = {
        **metadata,
        "run_id": None,
    }

    response = client.post(
        "/v1/telemetry/events",
        headers=authorization_header(
            "test-ingestor",
            "ingestor",
        ),
        json={
            "event_type": "flow",
            "timestamp": "2026-10-13T12:02:00Z",
            "src_ip": source_ip,
            "dest_ip": "198.51.100.1",
            "dest_port": 443,
            "proto": "TCP",
            "aegisgate_lab": metadata,
        },
    )

    assert response.status_code == 200, response.text
    created = response.json()

    assert created["status"] == expected_status
    assert created["telemetry"]["lab_metadata"] == expected_metadata
    assert "raw_event" not in created["telemetry"]

    listed_response = client.get(
        "/v1/events",
        headers=authorization_header(
            "test-soc-analyst",
            "soc_analyst",
        ),
    )

    assert listed_response.status_code == 200, listed_response.text

    matches = [
        event
        for event in listed_response.json()
        if event["event_id"] == created["event_id"]
    ]

    assert len(matches) == 1

    listed = matches[0]

    assert listed["status"] == expected_status
    assert listed["telemetry"]["lab_metadata"] == expected_metadata
    assert listed["telemetry"]["timestamp"] == (
        created["telemetry"]["timestamp"]
    )
    assert "raw_event" not in listed["telemetry"]

    if expected_status == "unresolved_asset":
        assert listed["risk_assessment"] is None
        assert listed["access_decision"]["action"] == "manual_review"


def test_persistent_api_unmarked_event_has_no_declared_lab_metadata() -> None:
    response = client.post(
        "/v1/telemetry/events",
        headers=authorization_header(
            "test-ingestor",
            "ingestor",
        ),
        json={
            "event_type": "flow",
            "timestamp": "2026-10-13T12:02:00Z",
            "src_ip": "10.10.10.99",
            "dest_ip": "198.51.100.1",
            "dest_port": 443,
            "proto": "TCP",
        },
    )

    assert response.status_code == 200, response.text
    created = response.json()

    assert created["telemetry"]["lab_metadata"] is None

    listed_response = client.get(
        "/v1/events",
        headers=authorization_header(
            "test-soc-analyst",
            "soc_analyst",
        ),
    )

    assert listed_response.status_code == 200, listed_response.text

    matches = [
        event
        for event in listed_response.json()
        if event["event_id"] == created["event_id"]
    ]

    assert len(matches) == 1
    assert matches[0]["telemetry"]["lab_metadata"] is None

def test_persistent_api_preserves_explicit_run_id() -> None:
    metadata = {
        "synthetic": True,
        "scenario": "both_thresholds_reached",
        "sequence": 1,
        "run_id": "persistence-run-001",
    }

    response = client.post(
        "/v1/telemetry/events",
        headers=authorization_header(
            "test-ingestor",
            "ingestor",
        ),
        json={
            "event_type": "flow",
            "timestamp": "2026-10-13T12:02:00Z",
            "src_ip": "10.10.10.99",
            "dest_ip": "198.51.100.1",
            "dest_port": 443,
            "proto": "TCP",
            "aegisgate_lab": metadata,
        },
    )

    assert response.status_code == 200, response.text
    created = response.json()

    assert created["telemetry"]["lab_metadata"] == metadata

    listed_response = client.get(
        "/v1/events",
        headers=authorization_header(
            "test-soc-analyst",
            "soc_analyst",
        ),
    )

    assert listed_response.status_code == 200, listed_response.text

    matches = [
        event
        for event in listed_response.json()
        if event["event_id"] == created["event_id"]
    ]

    assert len(matches) == 1
    assert matches[0]["telemetry"]["lab_metadata"] == metadata

@pytest.mark.parametrize(
    (
        "run_id_filter",
        "expected_count",
        "expected_destination_count",
        "expected_port_count",
        "expected_pattern",
    ),
    [
        (
            "summary-run-a",
            3,
            3,
            1,
            "destination_threshold_only",
        ),
        (
            "summary-run-b",
            3,
            1,
            3,
            "port_threshold_only",
        ),
        (
            "summary-run-missing",
            0,
            0,
            0,
            "neither_threshold_reached",
        ),
        (
            None,
            7,
            4,
            4,
            "both_thresholds_reached",
        ),
    ],
)
def test_network_summary_run_id_filter(
    run_id_filter,
    expected_count,
    expected_destination_count,
    expected_port_count,
    expected_pattern,
) -> None:
    observations = [
        ("summary-run-a", "198.51.100.1", 443),
        ("summary-run-a", "198.51.100.2", 443),
        ("summary-run-a", "198.51.100.3", 443),
        ("summary-run-b", "198.51.100.1", 22),
        ("summary-run-b", "198.51.100.1", 80),
        ("summary-run-b", "198.51.100.1", 443),
        (None, "198.51.100.4", 8080),
    ]

    event_ids_by_run = {
        "summary-run-a": set(),
        "summary-run-b": set(),
        None: set(),
    }

    for sequence, (run_id, destination, port) in enumerate(
        observations,
        start=1,
    ):
        payload = {
            "event_type": "flow",
            "timestamp": "2026-10-13T12:02:00Z",
            "src_ip": "10.10.10.99",
            "dest_ip": destination,
            "dest_port": port,
            "proto": "TCP",
        }

        if run_id is not None:
            payload["aegisgate_lab"] = {
                "synthetic": True,
                "scenario": "network_summary_run_filter_test",
                "sequence": sequence,
                "run_id": run_id,
            }

        created_response = client.post(
            "/v1/telemetry/events",
            headers=authorization_header(
                "test-ingestor",
                "ingestor",
            ),
            json=payload,
        )

        assert created_response.status_code == 200, (
            created_response.text
        )

        created = created_response.json()
        event_ids_by_run[run_id].add(created["event_id"])

    all_event_ids = set().union(*event_ids_by_run.values())
    assert len(all_event_ids) == 7

    params = {
        "source_ip": "10.10.10.99",
        "window_end": "2026-10-13T12:05:00Z",
        "window_minutes": 5,
        "destination_threshold": 3,
        "port_threshold": 3,
    }

    if run_id_filter is not None:
        params["run_id"] = run_id_filter

    response = client.get(
        "/v1/behavior/network-summary",
        headers=authorization_header(
            "test-soc-analyst",
            "soc_analyst",
        ),
        params=params,
    )

    assert response.status_code == 200, response.text
    summary = response.json()

    expected_event_ids = (
        all_event_ids
        if run_id_filter is None
        else event_ids_by_run.get(run_id_filter, set())
    )

    assert summary["run_id_filter"] == run_id_filter
    assert summary["source_record_count"] == expected_count
    assert summary["pattern"] == expected_pattern
    assert summary["triggered"] == (
        expected_pattern != "neither_threshold_reached"
    )

    destinations = summary["destination_analysis"]
    ports = summary["port_analysis"]

    assert destinations["unique_destination_count"] == (
        expected_destination_count
    )
    assert ports["unique_port_count"] == expected_port_count

    assert destinations["matching_record_count"] == expected_count
    assert ports["matching_record_count"] == expected_count

    assert set(summary["evidence_event_ids"]) == expected_event_ids
    assert set(summary["shared_evidence_event_ids"]) == (
        expected_event_ids
    )
    assert set(destinations["evidence_event_ids"]) == (
        expected_event_ids
    )
    assert set(ports["evidence_event_ids"]) == expected_event_ids

    assert summary["destination_only_evidence_event_ids"] == []
    assert summary["port_only_evidence_event_ids"] == []
