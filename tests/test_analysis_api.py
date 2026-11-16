"""API tests for the analysis core: run, detections, findings, RBAC, audit."""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

sys.path.append(str(Path(__file__).resolve().parents[1] / "backend"))

import app.main as api
from app.analysis_models import DetectionRecord, FindingRecord
from app.db_models import AuditLogRecord
from security import create_access_token

T0 = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)
KNOWN = "10.10.10.25"      # LAB-WS-001 in data/assets.json
UNKNOWN = "10.10.10.99"    # not in the inventory


def auth(role="soc_analyst"):
    token = create_access_token(username=f"test-{role}", role=role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def isolated_api(tmp_path, monkeypatch):
    test_engine = create_engine(
        f"sqlite:///{(tmp_path / 'analysis_test.db').as_posix()}",
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


def ingest(client, source, destination, port, seconds, **extra):
    event = {
        "event_type": "flow",
        "timestamp": (T0 + timedelta(seconds=seconds)).isoformat(),
        "src_ip": source, "dest_ip": destination, "dest_port": port, "proto": "TCP", **extra,
    }
    response = client.post("/v1/telemetry/events", headers=auth("ingestor"), json=event)
    assert response.status_code == 200, response.text
    return response.json()["event_id"]


def port_scan(client, source=KNOWN, count=16, start=0, **extra):
    return [ingest(client, source, "10.10.10.80", 1000 + i, start + i, **extra) for i in range(count)]


def run(client, role="soc_analyst", **body):
    return client.post("/api/v1/analysis/run", headers=auth(role), json=body or None)


def test_analysis_requires_authentication_and_role(isolated_api):
    client, _ = isolated_api
    assert client.post("/api/v1/analysis/run").status_code == 401
    assert run(client, "ingestor").status_code == 403
    for path in ("/api/v1/detections", "/api/v1/findings"):
        assert client.get(path).status_code == 401
        assert client.get(path, headers=auth("ingestor")).status_code == 403


def test_empty_database_gives_no_findings(isolated_api):
    client, _ = isolated_api
    response = run(client)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["events_analysed"] == 0 and body["detection_count"] == 0 and body["finding_count"] == 0
    assert client.get("/api/v1/findings", headers=auth()).json() == {
        "total": 0, "limit": 100, "offset": 0, "items": []}


def test_port_scan_is_detected_scored_and_decided(isolated_api):
    client, _ = isolated_api
    event_ids = port_scan(client)
    summary = run(client).json()
    assert summary["events_analysed"] == 16
    assert summary["detections_by_rule"] == {"DET-001": 1}
    assert summary["finding_count"] == 1

    listing = client.get("/api/v1/findings", headers=auth()).json()
    assert listing["total"] == 1
    item = listing["items"][0]
    assert item["finding"] == "port_scan" and item["source_ip"] == KNOWN
    assert item["asset_id"] == "lab-workstation-001"
    assert 20 <= item["risk_score"] < 40 and item["risk_level"] == "low"
    assert item["decision"] == "allow_with_monitoring"

    detail = client.get(f"/api/v1/findings/{item['group_id']}", headers=auth()).json()
    assert detail["risk_assessment"]["asset_criticality"] == "high"
    assert detail["risk_assessment"]["factors"][0]["factor"] == "evidence_port_scan"
    assert "behavioural_baseline" in detail["risk_assessment"]["missing_context"]
    assert detail["policy_decision"]["policy_version"] == "policy-academic-1.0"
    assert detail["baseline"]["status"] == "insufficient_baseline_data"
    (detection,) = detail["detections"]
    assert detection["rule_id"] == "DET-001" and sorted(detection["supporting_events"]) == sorted(event_ids)
    assert detection["observations"]["distinct_port_count"] == 16


def test_below_threshold_traffic_creates_nothing(isolated_api):
    client, _ = isolated_api
    port_scan(client, count=10)
    assert run(client).json()["detection_count"] == 0


def test_unknown_source_goes_to_manual_review(isolated_api):
    client, _ = isolated_api
    port_scan(client, source=UNKNOWN)
    run(client)
    (item,) = client.get("/api/v1/findings", headers=auth()).json()["items"]
    assert item["asset_id"] is None and item["decision"] == "manual_review"
    detail = client.get(f"/api/v1/findings/{item['group_id']}", headers=auth()).json()
    assert detail["risk_assessment"]["asset_identified"] is False
    assert "asset_identity" in detail["risk_assessment"]["missing_context"]


def test_repeating_the_run_does_not_duplicate(isolated_api):
    client, session_factory = isolated_api
    port_scan(client)
    first, second = run(client).json(), run(client).json()
    assert first["detections_by_rule"] == second["detections_by_rule"]
    with session_factory() as session:
        assert len(session.scalars(select(DetectionRecord)).all()) == 1
        assert len(session.scalars(select(FindingRecord)).all()) == 1


def test_new_evidence_supersedes_but_keeps_earlier_finding(isolated_api):
    client, _ = isolated_api
    port_scan(client)
    run(client)
    (before,) = client.get("/api/v1/findings", headers=auth()).json()["items"]
    for i in range(12):                                  # host sweep by the same source
        ingest(client, KNOWN, f"10.10.10.{100 + i}", 445, 30 + i)
    run(client)
    (after,) = client.get("/api/v1/findings", headers=auth()).json()["items"]
    assert after["group_id"] != before["group_id"]
    assert after["finding"] == "potential_network_reconnaissance"
    assert after["risk_score"] > before["risk_score"]
    history = client.get("/api/v1/findings", headers=auth(), params={"include_superseded": True}).json()
    assert history["total"] == 2
    old = client.get(f"/api/v1/findings/{before['group_id']}", headers=auth()).json()
    assert old["is_current"] is False


def test_run_scoped_to_run_id_ignores_other_events(isolated_api):
    client, _ = isolated_api
    lab = {"aegisgate_lab": {"synthetic": True, "scenario": "port_scan", "sequence": 1, "run_id": "run-a"}}
    port_scan(client, source=UNKNOWN, **lab)
    port_scan(client, source=KNOWN, start=5)
    summary = run(client, run_id="run-a").json()
    assert summary["scope"] == "run-a" and summary["events_analysed"] == 16
    (item,) = client.get("/api/v1/findings", headers=auth()).json()["items"]
    assert item["source_ip"] == UNKNOWN and item["scope"] == "run-a"


def test_detection_filters_and_lookup(isolated_api):
    client, _ = isolated_api
    port_scan(client)
    run(client)
    listing = client.get("/api/v1/detections", headers=auth(), params={"rule_id": "DET-001"}).json()
    assert listing["total"] == 1
    detection_id = listing["items"][0]["detection_id"]
    assert client.get(f"/api/v1/detections/{detection_id}", headers=auth()).json()["category"] == "port_scan"
    assert client.get("/api/v1/detections", headers=auth(), params={"severity": "high"}).json()["total"] == 0
    assert client.get("/api/v1/detections", headers=auth(), params={"severity": "urgent"}).status_code == 422
    assert client.get("/api/v1/detections/det-missing", headers=auth()).status_code == 404
    assert client.get("/api/v1/findings/grp-missing", headers=auth()).status_code == 404


@pytest.mark.parametrize("run_id", ["", "bad id", "-leading", "x" * 101, "a'; DROP TABLE alerts;--"])
def test_invalid_run_id_is_rejected(isolated_api, run_id):
    client, _ = isolated_api
    assert run(client, run_id=run_id).status_code == 422


def test_analysis_run_is_audited(isolated_api):
    client, session_factory = isolated_api
    port_scan(client)
    run(client, "security_admin")
    with session_factory() as session:
        (entry,) = session.scalars(
            select(AuditLogRecord).where(AuditLogRecord.action == "analysis_run")).all()
    assert entry.actor == "test-security_admin" and entry.target_id == "all-events"
    assert entry.details_json["detection_count"] == 1 and entry.details_json["versions"]["policy"]
