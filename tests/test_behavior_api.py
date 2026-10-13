import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker


sys.path.append(
    str(Path(__file__).resolve().parents[1] / "backend")
)

import app.main as api
from app.db_models import AuditLogRecord
from security import create_access_token


PATH = "/v1/behavior/destination-diversity"

DEFAULT_PARAMS = {
    "source_ip": "10.10.10.99",
    "window_end": "2026-10-12T20:05:00Z",
    "window_minutes": 5,
    "destination_threshold": 3,
}


def auth(role="soc_analyst"):
    token = create_access_token(
        username=f"test-{role}",
        role=role,
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def isolated_api(tmp_path, monkeypatch):
    database_path = tmp_path / "behavior_test.db"

    test_engine = create_engine(
        f"sqlite:///{database_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )

    session_factory = sessionmaker(bind=test_engine)

    def override_get_db():
        with session_factory() as session:
            yield session

    previous_overrides = api.app.dependency_overrides.copy()

    monkeypatch.setattr(api, "engine", test_engine)
    api.app.dependency_overrides[api.get_db] = override_get_db

    try:
        with TestClient(api.app) as client:
            yield client, session_factory
    finally:
        api.app.dependency_overrides.clear()
        api.app.dependency_overrides.update(previous_overrides)
        test_engine.dispose()


def ingest(client, destination, timestamp):
    response = client.post(
        "/v1/telemetry/events",
        headers=auth("ingestor"),
        json={
            "event_type": "flow",
            "timestamp": timestamp,
            "src_ip": "10.10.10.99",
            "dest_ip": destination,
            "dest_port": 443,
            "proto": "TCP",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "unresolved_asset"

    return response.json()["event_id"]


def populate(client):
    included = [
        ingest(client, "198.51.100.1", "2026-10-12T20:00:00Z"),
        ingest(client, "198.51.100.2", "2026-10-12T20:02:00Z"),
        ingest(client, "198.51.100.3", "2026-10-12T20:05:00Z"),
    ]

    excluded = [
        ingest(client, "198.51.100.4", "2026-10-12T19:59:59Z"),
        ingest(client, "198.51.100.5", "2026-10-12T20:05:01Z"),
    ]

    return included, excluded


def test_behavior_requires_authentication(isolated_api):
    client, _ = isolated_api

    response = client.get(PATH, params=DEFAULT_PARAMS)

    assert response.status_code == 401


def test_ingestor_cannot_analyze_behavior(isolated_api):
    client, _ = isolated_api

    response = client.get(
        PATH,
        params=DEFAULT_PARAMS,
        headers=auth("ingestor"),
    )

    assert response.status_code == 403


@pytest.mark.parametrize("role", ["soc_analyst", "security_admin"])
def test_authorized_roles_can_analyze_empty_history(isolated_api, role):
    client, _ = isolated_api

    response = client.get(
        PATH,
        params=DEFAULT_PARAMS,
        headers=auth(role),
    )

    assert response.status_code == 200
    result = response.json()

    assert result["unique_destination_count"] == 0
    assert result["evidence_event_ids"] == []
    assert result["triggered"] is False
    assert result["scope"] == "persisted_local_telemetry_only"


def test_behavior_positive_negative_and_evidence(isolated_api):
    client, _ = isolated_api
    included, excluded = populate(client)

    response = client.get(
        PATH,
        params=DEFAULT_PARAMS,
        headers=auth(),
    )

    assert response.status_code == 200
    result = response.json()

    assert result["unique_destination_count"] == 3
    assert result["matching_record_count"] == 3
    assert result["source_record_count"] == 5
    assert result["triggered"] is True

    assert set(result["evidence_event_ids"]) == set(included)
    assert not set(excluded) & set(result["evidence_event_ids"])

    negative_response = client.get(
        PATH,
        params={
            **DEFAULT_PARAMS,
            "destination_threshold": 4,
        },
        headers=auth(),
    )

    assert negative_response.status_code == 200
    assert negative_response.json()["triggered"] is False


def test_behavior_records_audit_entry(isolated_api):
    client, session_factory = isolated_api
    populate(client)

    response = client.get(
        PATH,
        params=DEFAULT_PARAMS,
        headers=auth(),
    )

    assert response.status_code == 200

    with session_factory() as session:
        entries = session.scalars(
            select(AuditLogRecord).where(
                AuditLogRecord.action
                == "destination_diversity_analysis_requested"
            )
        ).all()

        assert len(entries) == 1

        entry = entries[0]
        assert entry.actor == "test-soc_analyst"
        assert entry.target_id == "10.10.10.99"
        assert entry.details_json["triggered"] is True
        assert entry.details_json["unique_destination_count"] == 3
        assert set(entry.details_json["evidence_event_ids"]) == set(
            response.json()["evidence_event_ids"]
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"window_end": "2026-10-12T20:05:00"},
        {"window_end": "invalid"},
        {"window_minutes": 0},
        {"window_minutes": 1441},
        {"destination_threshold": 1},
        {"destination_threshold": 10001},
    ],
)
def test_invalid_parameters_are_rejected(isolated_api, changes):
    client, _ = isolated_api

    response = client.get(
        PATH,
        params={**DEFAULT_PARAMS, **changes},
        headers=auth(),
    )

    assert response.status_code == 422


def test_missing_window_end_is_rejected(isolated_api):
    client, _ = isolated_api
    params = DEFAULT_PARAMS.copy()
    params.pop("window_end")

    response = client.get(
        PATH,
        params=params,
        headers=auth(),
    )

    assert response.status_code == 422


PORT_PATH = "/v1/behavior/port-diversity"

PORT_PARAMS = {
    "source_ip": "10.10.10.99",
    "window_end": "2026-10-12T20:05:00Z",
    "window_minutes": 5,
    "port_threshold": 3,
}


def ingest_port(
    client,
    port,
    timestamp,
    destination="198.51.100.1",
    source="10.10.10.99",
):
    response = client.post(
        "/v1/telemetry/events",
        headers=auth("ingestor"),
        json={
            "event_type": "flow",
            "timestamp": timestamp,
            "src_ip": source,
            "dest_ip": destination,
            "dest_port": port,
            "proto": "TCP",
        },
    )

    assert response.status_code == 200, response.text

    return response.json()["event_id"]


def populate_ports(client):
    included = [
        ingest_port(client, 22, "2026-10-12T20:00:00Z"),
        ingest_port(client, 80, "2026-10-12T20:02:00Z"),
        ingest_port(client, 443, "2026-10-12T20:05:00Z"),
    ]

    excluded = [
        ingest_port(client, 8080, "2026-10-12T19:59:59Z"),
        ingest_port(client, 8443, "2026-10-12T20:05:01Z"),
    ]

    return included, excluded


def test_port_api_requires_authentication(isolated_api):
    client, _ = isolated_api

    response = client.get(PORT_PATH, params=PORT_PARAMS)

    assert response.status_code == 401


def test_port_api_ingestor_is_forbidden(isolated_api):
    client, _ = isolated_api

    response = client.get(
        PORT_PATH,
        params=PORT_PARAMS,
        headers=auth("ingestor"),
    )

    assert response.status_code == 403


@pytest.mark.parametrize("role", ["soc_analyst", "security_admin"])
def test_port_api_authorized_roles_empty_history(isolated_api, role):
    client, _ = isolated_api

    response = client.get(
        PORT_PATH,
        params=PORT_PARAMS,
        headers=auth(role),
    )

    assert response.status_code == 200, response.text
    result = response.json()

    assert result["analysis_type"] == "port_diversity"
    assert result["unique_port_count"] == 0
    assert result["observed_ports"] == []
    assert result["evidence_event_ids"] == []
    assert result["triggered"] is False
    assert result["scope"] == "persisted_local_telemetry_only"
    assert result["analysis_version"] == "port-diversity-v1"


def test_port_api_threshold_window_and_evidence(isolated_api):
    client, _ = isolated_api
    included, excluded = populate_ports(client)

    response = client.get(
        PORT_PATH,
        params=PORT_PARAMS,
        headers=auth(),
    )

    assert response.status_code == 200, response.text
    result = response.json()

    assert result["unique_port_count"] == 3
    assert result["observed_ports"] == [22, 80, 443]
    assert result["matching_record_count"] == 3
    assert result["source_record_count"] == 5
    assert result["triggered"] is True
    assert result["ports_by_destination"] == {
        "198.51.100.1": [22, 80, 443],
    }
    assert set(result["evidence_event_ids"]) == set(included)
    assert not set(excluded) & set(result["evidence_event_ids"])

    negative_response = client.get(
        PORT_PATH,
        params={**PORT_PARAMS, "port_threshold": 4},
        headers=auth(),
    )

    assert negative_response.status_code == 200
    assert negative_response.json()["triggered"] is False


def test_port_api_duplicate_ports_across_destinations(isolated_api):
    client, _ = isolated_api

    first_id = ingest_port(
        client,
        443,
        "2026-10-12T20:02:00Z",
        destination="198.51.100.1",
    )
    second_id = ingest_port(
        client,
        443,
        "2026-10-12T20:03:00Z",
        destination="198.51.100.2",
    )

    response = client.get(
        PORT_PATH,
        params=PORT_PARAMS,
        headers=auth(),
    )

    assert response.status_code == 200, response.text
    result = response.json()

    assert result["unique_port_count"] == 1
    assert result["matching_record_count"] == 2
    assert result["triggered"] is False
    assert result["ports_by_destination"] == {
        "198.51.100.1": [443],
        "198.51.100.2": [443],
    }
    assert set(result["evidence_event_ids"]) == {
        first_id,
        second_id,
    }


def test_port_api_destination_filter(isolated_api):
    client, _ = isolated_api

    included_id = ingest_port(
        client,
        22,
        "2026-10-12T20:02:00Z",
        destination="198.51.100.1",
    )
    excluded_id = ingest_port(
        client,
        443,
        "2026-10-12T20:03:00Z",
        destination="198.51.100.2",
    )

    response = client.get(
        PORT_PATH,
        params={
            **PORT_PARAMS,
            "destination_ip": "198.51.100.1",
        },
        headers=auth(),
    )

    assert response.status_code == 200, response.text
    result = response.json()

    assert result["destination_filter"] == "198.51.100.1"
    assert result["observed_ports"] == [22]
    assert result["matching_record_count"] == 1
    assert result["source_record_count"] == 2
    assert result["evidence_event_ids"] == [included_id]
    assert excluded_id not in result["evidence_event_ids"]


def test_port_api_excludes_other_sources(isolated_api):
    client, _ = isolated_api

    included_id = ingest_port(
        client,
        22,
        "2026-10-12T20:02:00Z",
    )
    excluded_id = ingest_port(
        client,
        443,
        "2026-10-12T20:03:00Z",
        source="10.10.10.98",
    )

    response = client.get(
        PORT_PATH,
        params=PORT_PARAMS,
        headers=auth(),
    )

    assert response.status_code == 200, response.text
    result = response.json()

    assert result["source_record_count"] == 1
    assert result["observed_ports"] == [22]
    assert result["evidence_event_ids"] == [included_id]
    assert excluded_id not in result["evidence_event_ids"]


def test_port_api_records_audit_entry(isolated_api):
    client, session_factory = isolated_api
    included, _ = populate_ports(client)

    response = client.get(
        PORT_PATH,
        params=PORT_PARAMS,
        headers=auth(),
    )

    assert response.status_code == 200, response.text

    with session_factory() as session:
        entries = session.scalars(
            select(AuditLogRecord).where(
                AuditLogRecord.action
                == "port_diversity_analysis_requested"
            )
        ).all()

        assert len(entries) == 1
        entry = entries[0]

        assert entry.actor == "test-soc_analyst"
        assert entry.target_type == "ip_address"
        assert entry.target_id == "10.10.10.99"

        details = entry.details_json
        assert details["triggered"] is True
        assert details["port_threshold"] == 3
        assert details["unique_port_count"] == 3
        assert details["observed_ports"] == [22, 80, 443]
        assert details["destination_filter"] is None
        assert details["analysis_version"] == "port-diversity-v1"
        assert set(details["evidence_event_ids"]) == set(included)


@pytest.mark.parametrize(
    "changes",
    [
        {"window_end": "2026-10-12T20:05:00"},
        {"window_end": "invalid"},
        {"window_minutes": 0},
        {"window_minutes": 1441},
        {"port_threshold": 1},
        {"port_threshold": 65536},
        {"destination_ip": ""},
    ],
)
def test_port_api_invalid_parameters(isolated_api, changes):
    client, _ = isolated_api

    response = client.get(
        PORT_PATH,
        params={**PORT_PARAMS, **changes},
        headers=auth(),
    )

    assert response.status_code == 422, response.text


@pytest.mark.parametrize("missing", ["source_ip", "window_end"])
def test_port_api_missing_required_parameters(isolated_api, missing):
    client, _ = isolated_api
    params = PORT_PARAMS.copy()
    params.pop(missing)

    response = client.get(
        PORT_PATH,
        params=params,
        headers=auth(),
    )

    assert response.status_code == 422, response.text

SUMMARY_PATH = "/v1/behavior/network-summary"

SUMMARY_PARAMS = {
    "source_ip": "10.10.10.99",
    "window_end": "2026-10-12T20:05:00Z",
    "window_minutes": 5,
    "destination_threshold": 2,
    "port_threshold": 2,
}


def test_summary_api_requires_authentication(isolated_api):
    client, _ = isolated_api

    response = client.get(
        SUMMARY_PATH,
        params=SUMMARY_PARAMS,
    )

    assert response.status_code == 401


def test_summary_api_ingestor_is_forbidden(isolated_api):
    client, _ = isolated_api

    response = client.get(
        SUMMARY_PATH,
        params=SUMMARY_PARAMS,
        headers=auth("ingestor"),
    )

    assert response.status_code == 403


@pytest.mark.parametrize("role", ["soc_analyst", "security_admin"])
def test_summary_api_authorized_roles_empty_history(isolated_api, role):
    client, _ = isolated_api

    response = client.get(
        SUMMARY_PATH,
        params=SUMMARY_PARAMS,
        headers=auth(role),
    )

    assert response.status_code == 200, response.text
    result = response.json()

    assert result["analysis_type"] == "network_behavior_summary"
    assert result["pattern"] == "neither_threshold_reached"
    assert result["triggered"] is False
    assert result["source_record_count"] == 0
    assert result["evidence_event_ids"] == []
    assert result["shared_evidence_event_ids"] == []
    assert result["destination_only_evidence_event_ids"] == []
    assert result["port_only_evidence_event_ids"] == []
    assert result["scope"] == "persisted_local_telemetry_only"
    assert result["analysis_version"] == "network-summary-v1"

    assert result["destination_analysis"]["unique_destination_count"] == 0
    assert result["port_analysis"]["unique_port_count"] == 0


@pytest.mark.parametrize(
    "observations, expected_pattern, expected_triggered",
    [
        (
            [("198.51.100.1", 443)],
            "neither_threshold_reached",
            False,
        ),
        (
            [("198.51.100.1", 443), ("198.51.100.2", 443)],
            "destination_threshold_only",
            True,
        ),
        (
            [("198.51.100.1", 22), ("198.51.100.1", 443)],
            "port_threshold_only",
            True,
        ),
        (
            [("198.51.100.1", 22), ("198.51.100.2", 443)],
            "both_thresholds_reached",
            True,
        ),
    ],
)
def test_summary_api_four_patterns(
    isolated_api,
    observations,
    expected_pattern,
    expected_triggered,
):
    client, _ = isolated_api

    event_ids = [
        ingest_port(
            client,
            port,
            "2026-10-12T20:02:00Z",
            destination=destination,
        )
        for destination, port in observations
    ]

    response = client.get(
        SUMMARY_PATH,
        params=SUMMARY_PARAMS,
        headers=auth(),
    )

    assert response.status_code == 200, response.text
    result = response.json()

    assert result["pattern"] == expected_pattern
    assert result["triggered"] is expected_triggered
    assert result["source_record_count"] == len(observations)
    assert set(result["evidence_event_ids"]) == set(event_ids)
    assert set(result["shared_evidence_event_ids"]) == set(event_ids)
    assert result["destination_only_evidence_event_ids"] == []
    assert result["port_only_evidence_event_ids"] == []

    destinations = result["destination_analysis"]
    ports = result["port_analysis"]

    assert destinations["window_start"] == result["window_start"]
    assert ports["window_start"] == result["window_start"]
    assert destinations["window_end"] == result["window_end"]
    assert ports["window_end"] == result["window_end"]


def test_summary_api_window_source_and_evidence(isolated_api):
    client, _ = isolated_api

    included = [
        ingest_port(
            client,
            22,
            "2026-10-12T20:00:00Z",
            destination="198.51.100.1",
        ),
        ingest_port(
            client,
            443,
            "2026-10-12T20:05:00Z",
            destination="198.51.100.2",
        ),
    ]

    excluded = [
        ingest_port(client, 80, "2026-10-12T19:59:59Z"),
        ingest_port(client, 8080, "2026-10-12T20:05:01Z"),
        ingest_port(
            client,
            8443,
            "2026-10-12T20:02:00Z",
            source="10.10.10.98",
        ),
    ]

    response = client.get(
        SUMMARY_PATH,
        params=SUMMARY_PARAMS,
        headers=auth(),
    )

    assert response.status_code == 200, response.text
    result = response.json()

    assert result["pattern"] == "both_thresholds_reached"
    assert result["source_record_count"] == 4
    assert result["destination_analysis"]["matching_record_count"] == 2
    assert result["port_analysis"]["matching_record_count"] == 2
    assert set(result["evidence_event_ids"]) == set(included)
    assert set(result["shared_evidence_event_ids"]) == set(included)
    assert not set(excluded) & set(result["evidence_event_ids"])


def test_summary_api_records_audit_entry(isolated_api):
    client, session_factory = isolated_api

    event_ids = [
        ingest_port(
            client,
            22,
            "2026-10-12T20:02:00Z",
            destination="198.51.100.1",
        ),
        ingest_port(
            client,
            443,
            "2026-10-12T20:03:00Z",
            destination="198.51.100.2",
        ),
    ]

    response = client.get(
        SUMMARY_PATH,
        params=SUMMARY_PARAMS,
        headers=auth(),
    )

    assert response.status_code == 200, response.text

    with session_factory() as session:
        entries = session.scalars(
            select(AuditLogRecord).where(
                AuditLogRecord.action
                == "network_behavior_summary_requested"
            )
        ).all()

        assert len(entries) == 1
        entry = entries[0]

        assert entry.actor == "test-soc_analyst"
        assert entry.target_type == "ip_address"
        assert entry.target_id == "10.10.10.99"

        details = entry.details_json

        assert details["pattern"] == "both_thresholds_reached"
        assert details["triggered"] is True
        assert details["destination_threshold"] == 2
        assert details["port_threshold"] == 2
        assert details["unique_destination_count"] == 2
        assert details["unique_port_count"] == 2
        assert details["destination_signal_triggered"] is True
        assert details["port_signal_triggered"] is True
        assert details["source_record_count"] == 2
        assert details["analysis_version"] == "network-summary-v1"
        assert set(details["evidence_event_ids"]) == set(event_ids)
        assert set(details["shared_evidence_event_ids"]) == set(event_ids)


@pytest.mark.parametrize(
    "changes",
    [
        {"window_end": "2026-10-12T20:05:00"},
        {"window_end": "invalid"},
        {"window_minutes": 0},
        {"window_minutes": 1441},
        {"destination_threshold": 1},
        {"destination_threshold": 10001},
        {"port_threshold": 1},
        {"port_threshold": 65536},
    ],
)
def test_summary_api_invalid_parameters(isolated_api, changes):
    client, _ = isolated_api

    response = client.get(
        SUMMARY_PATH,
        params={**SUMMARY_PARAMS, **changes},
        headers=auth(),
    )

    assert response.status_code == 422, response.text


@pytest.mark.parametrize("missing", ["source_ip", "window_end"])
def test_summary_api_missing_required_parameters(isolated_api, missing):
    client, _ = isolated_api
    params = SUMMARY_PARAMS.copy()
    params.pop(missing)

    response = client.get(
        SUMMARY_PATH,
        params=params,
        headers=auth(),
    )

    assert response.status_code == 422, response.text

def test_summary_api_audits_run_id_filter_and_evidence(isolated_api):
    client, session_factory = isolated_api

    event_ids_by_run = {
        "summary-run-a": set(),
        "summary-run-b": set(),
    }

    observations = [
        ("summary-run-a", "198.51.100.1", 22),
        ("summary-run-a", "198.51.100.2", 443),
        ("summary-run-b", "198.51.100.3", 8080),
    ]

    for sequence, (run_id, destination, port) in enumerate(
        observations,
        start=1,
    ):
        created_response = client.post(
            "/v1/telemetry/events",
            headers=auth("ingestor"),
            json={
                "event_type": "flow",
                "timestamp": "2026-10-12T20:02:00Z",
                "src_ip": "10.10.10.99",
                "dest_ip": destination,
                "dest_port": port,
                "proto": "TCP",
                "aegisgate_lab": {
                    "synthetic": True,
                    "scenario": "summary_audit_run_filter_test",
                    "sequence": sequence,
                    "run_id": run_id,
                },
            },
        )

        assert created_response.status_code == 200, (
            created_response.text
        )

        event_ids_by_run[run_id].add(
            created_response.json()["event_id"]
        )

    response = client.get(
        SUMMARY_PATH,
        params={
            **SUMMARY_PARAMS,
            "source_ip": "10.10.10.99",
            "window_end": "2026-10-12T20:05:00Z",
            "window_minutes": 5,
            "destination_threshold": 2,
            "port_threshold": 2,
            "run_id": "summary-run-a",
        },
        headers=auth(),
    )

    assert response.status_code == 200, response.text
    summary = response.json()

    expected_ids = event_ids_by_run["summary-run-a"]
    excluded_ids = event_ids_by_run["summary-run-b"]

    assert len(expected_ids) == 2
    assert len(excluded_ids) == 1
    assert summary["run_id_filter"] == "summary-run-a"
    assert summary["source_record_count"] == 2
    assert summary["pattern"] == "both_thresholds_reached"
    assert set(summary["evidence_event_ids"]) == expected_ids
    assert not excluded_ids & set(summary["evidence_event_ids"])

    with session_factory() as session:
        entries = session.scalars(
            select(AuditLogRecord).where(
                AuditLogRecord.action
                == "network_behavior_summary_requested"
            )
        ).all()

        assert len(entries) == 1
        entry = entries[0]

        assert entry.actor == "test-soc_analyst"
        assert entry.target_type == "ip_address"
        assert entry.target_id == "10.10.10.99"

        details = entry.details_json

        for key in (
            "run_id_filter",
            "source_record_count",
            "pattern",
            "triggered",
            "window_start",
            "window_end",
            "window_minutes",
            "scope",
            "analysis_version",
        ):
            assert details[key] == summary[key]

        assert details["destination_threshold"] == 2
        assert details["port_threshold"] == 2
        assert details["unique_destination_count"] == 2
        assert details["unique_port_count"] == 2
        assert details["destination_matching_record_count"] == 2
        assert details["port_matching_record_count"] == 2

        for key in (
            "evidence_event_ids",
            "shared_evidence_event_ids",
            "destination_only_evidence_event_ids",
            "port_only_evidence_event_ids",
        ):
            assert details[key] == summary[key]

        assert set(details["evidence_event_ids"]) == expected_ids
        assert not excluded_ids & set(details["evidence_event_ids"])
