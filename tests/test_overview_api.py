"""Dashboard overview and asset inventory: numbers must come from stored rows."""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.append(str(Path(__file__).resolve().parents[1] / "backend"))

import app.main as api
from security import create_access_token

T0 = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)
KNOWN, UNKNOWN = "10.10.10.25", "10.10.10.99"


def auth(role="soc_analyst"):
    return {"Authorization": f"Bearer {create_access_token(username=f'test-{role}', role=role)}"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    test_engine = create_engine(
        f"sqlite:///{(tmp_path / 'overview_test.db').as_posix()}",
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
        with TestClient(api.app) as test_client:
            yield test_client
    finally:
        api.app.dependency_overrides.clear()
        api.app.dependency_overrides.update(previous_overrides)
        test_engine.dispose()


def scan(client, source, count=16):
    ids = []
    for i in range(count):
        response = client.post("/v1/telemetry/events", headers=auth("ingestor"), json={
            "event_type": "flow", "timestamp": (T0 + timedelta(seconds=i)).isoformat(),
            "src_ip": source, "dest_ip": "10.10.10.80", "dest_port": 1000 + i, "proto": "TCP"})
        assert response.status_code == 200, response.text
        ids.append(response.json()["event_id"])
    return ids


def test_overview_and_assets_require_a_reading_role(client):
    for path in ("/api/v1/dashboard/overview", "/api/v1/assets"):
        assert client.get(path).status_code == 401
        assert client.get(path, headers=auth("ingestor")).status_code == 403
        assert client.get(path, headers=auth("viewer")).status_code == 200


def test_empty_system_reports_zeros_and_nulls_not_invented_values(client):
    body = client.get("/api/v1/dashboard/overview", headers=auth()).json()
    assert body["academic_mode"] is True
    assert body["counts"] == {
        "monitored_assets": 2, "unidentified_sources": 0, "events": 0, "current_detections": 0,
        "current_findings": 0, "open_investigations": 0, "response_actions": 0}
    assert body["highest_risk"] is None and body["detection_trend"] == [] and body["recent_events"] == []
    assert body["assets_by_status"] == {"normal": 2, "under_review": 0, "at_risk": 0, "unknown": 0}
    assert body["system"]["last_analysis_at"] is None


def test_overview_reflects_ingested_events_and_analysis(client):
    scan(client, KNOWN)
    scan(client, UNKNOWN)
    before = client.get("/api/v1/dashboard/overview", headers=auth()).json()
    assert before["counts"]["events"] == 32 and before["counts"]["current_findings"] == 0
    assert before["counts"]["unidentified_sources"] == 1

    assert client.post("/api/v1/analysis/run", headers=auth()).status_code == 200
    body = client.get("/api/v1/dashboard/overview", headers=auth()).json()
    assert body["counts"]["current_detections"] == 2 and body["counts"]["current_findings"] == 2
    assert sum(body["findings_by_level"].values()) == 2
    assert body["highest_risk"]["source_ip"] == UNKNOWN          # +5 for unidentified source
    assert body["attention"]["findings_awaiting_review"] == 1
    assert body["assets_by_status"] == {"normal": 1, "under_review": 1, "at_risk": 0, "unknown": 1}
    assert len(body["detection_trend"]) == 24
    assert sum(hour["medium"] for hour in body["detection_trend"]) == 2
    assert body["detection_trend"][-1]["hour"] == "2026-11-15T12:00:00+00:00"
    assert len(body["recent_events"]) == 8
    assert body["recent_events"][0]["timestamp"] >= body["recent_events"][-1]["timestamp"]
    assert body["system"]["last_analysis_at"] is not None


def test_open_investigations_count_comes_from_cases(client):
    event_id = scan(client, KNOWN, count=1)[0]
    created = client.post(f"/v1/events/{event_id}/case", headers=auth(), json={"title": "Check scan"})
    assert created.status_code == 200, created.text
    body = client.get("/api/v1/dashboard/overview", headers=auth()).json()
    assert body["counts"]["open_investigations"] == 1
    case_id = created.json()["case_id"]
    client.patch(f"/v1/cases/{case_id}", headers=auth(),
                 json={"status": "resolved", "analyst_note": "Authorised test."})
    body = client.get("/api/v1/dashboard/overview", headers=auth()).json()
    assert body["counts"]["open_investigations"] == 0


def test_assets_list_inventory_and_unidentified_sources(client):
    scan(client, KNOWN)
    scan(client, UNKNOWN)
    client.post("/api/v1/analysis/run", headers=auth())
    body = client.get("/api/v1/assets", headers=auth()).json()
    assert body["total"] == 3
    by_ip = {item["ip_address"]: item for item in body["items"]}
    known = by_ip[KNOWN]
    assert known["device_name"] == "LAB-WS-001" and known["criticality"] == "high"
    assert known["status"] == "under_review" and known["event_count"] == 16
    assert known["detection_count"] == 1 and 20 <= known["highest_risk"] < 40
    unknown = by_ip[UNKNOWN]
    assert unknown["identified"] is False and unknown["status"] == "unknown"
    assert unknown["asset_id"] is None and unknown["device_name"] is None and unknown["criticality"] is None
    idle = by_ip["10.10.10.50"]
    assert idle["status"] == "normal" and idle["event_count"] == 0 and idle["last_seen"] is None
