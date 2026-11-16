"""Simulated responses, audit trail integrity and Demo Lab, through the API."""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

sys.path.append(str(Path(__file__).resolve().parents[1] / "backend"))

import app.main as api
from app.core import scenarios
from app.db_models import AlertRecord, AuditLogRecord
from app.platform_models import AuditSealRecord
from security import create_access_token

T0 = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)
KNOWN = "10.10.10.25"


def auth(role="soc_analyst"):
    return {"Authorization": f"Bearer {create_access_token(username=f'test-{role}', role=role)}"}


ADMIN, ANALYST, VIEWER = "security_admin", "soc_analyst", "viewer"


@pytest.fixture
def isolated_api(tmp_path, monkeypatch):
    test_engine = create_engine(
        f"sqlite:///{(tmp_path / 'platform_test.db').as_posix()}",
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


def finding_id(client):
    """Ingest a small port scan, analyse it, return the finding identifier."""
    for i in range(16):
        response = client.post("/v1/telemetry/events", headers=auth("ingestor"), json={
            "event_type": "flow", "timestamp": (T0 + timedelta(seconds=i)).isoformat(),
            "src_ip": KNOWN, "dest_ip": "10.10.10.80", "dest_port": 1000 + i, "proto": "TCP"})
        assert response.status_code == 200, response.text
    assert client.post("/api/v1/analysis/run", headers=auth()).status_code == 200
    return client.get("/api/v1/findings", headers=auth()).json()["items"][0]["group_id"]


def request_action(client, group_id, action_type, role=ANALYST, reason="Scan confirmed by analyst"):
    return client.post("/api/v1/responses", headers=auth(role),
                       json={"group_id": group_id, "action_type": action_type, "reason": reason})


def change(client, action_id, operation, role=ANALYST, note=None):
    return client.post(f"/api/v1/responses/{action_id}/{operation}", headers=auth(role),
                       json={"note": note} if note is not None else None)


# ---- simulated responses -----------------------------------------------------------

def test_low_impact_action_is_executed_in_simulation_at_once(isolated_api):
    client, _ = isolated_api
    response = request_action(client, finding_id(client), "monitor")
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["state"] == "executed_in_simulation" and body["simulated"] is True
    assert body["outcome"]["real_infrastructure_changed"] is False
    assert body["outcome"]["target_state"] == "monitored" and body["source_ip"] == KNOWN
    assert [step["operation"] for step in body["history"]] == ["request", "execute"]


def test_high_impact_action_needs_administrator_approval_and_can_be_rolled_back(isolated_api):
    client, _ = isolated_api
    group_id = finding_id(client)
    created = request_action(client, group_id, "simulated_host_quarantine").json()
    assert created["state"] == "pending_approval" and created["outcome"] is None
    action_id = created["action_id"]

    assert change(client, action_id, "execute").status_code == 409            # not approved yet
    assert change(client, action_id, "approve", ANALYST).status_code == 403   # analysts cannot approve
    assert change(client, action_id, "approve", ADMIN).json()["state"] == "approved"
    executed = change(client, action_id, "execute").json()
    assert executed["state"] == "executed_in_simulation"
    assert executed["outcome"]["target_state"] == "quarantined"
    assert "No real isolation" in executed["outcome"]["effect"]

    assert change(client, action_id, "rollback").status_code == 422           # reason required
    rolled = change(client, action_id, "rollback", note="False alarm, authorised test").json()
    assert rolled["state"] == "rolled_back" and rolled["outcome"]["target_state"] == "normal"
    assert [s["operation"] for s in rolled["history"]] == ["request", "approve", "execute", "rollback"]
    assert rolled["history"][1]["by"] == "test-security_admin"
    assert change(client, action_id, "rollback", note="again please").status_code == 409


def test_rejection_requires_a_reason_and_ends_the_action(isolated_api):
    client, _ = isolated_api
    action_id = request_action(client, finding_id(client), "simulated_connection_block").json()["action_id"]
    assert change(client, action_id, "reject", ADMIN).status_code == 422
    assert change(client, action_id, "reject", ADMIN, note="Not enough evidence").json()["state"] == "rejected"
    assert change(client, action_id, "execute", ADMIN).status_code == 409


def test_duplicate_active_action_is_refused_but_allowed_again_after_rollback(isolated_api):
    client, _ = isolated_api
    group_id = finding_id(client)
    first = request_action(client, group_id, "monitor").json()
    assert request_action(client, group_id, "monitor").status_code == 409
    change(client, first["action_id"], "rollback", note="No longer needed")
    assert request_action(client, group_id, "monitor").status_code == 201


def test_response_permissions_and_validation(isolated_api):
    client, _ = isolated_api
    group_id = finding_id(client)
    assert client.post("/api/v1/responses", json={
        "group_id": group_id, "action_type": "monitor", "reason": "anonymous"}).status_code == 401
    assert request_action(client, group_id, "monitor", VIEWER).status_code == 403
    assert request_action(client, group_id, "monitor", "ingestor").status_code == 403
    assert request_action(client, group_id, "real_firewall_block").status_code == 422
    assert request_action(client, group_id, "monitor", reason="no").status_code == 422
    assert request_action(client, "grp-missing", "monitor").status_code == 404
    assert change(client, "missing-action", "execute").status_code == 404
    action_id = request_action(client, group_id, "monitor").json()["action_id"]
    assert change(client, action_id, "delete").status_code == 404
    assert change(client, action_id, "rollback", VIEWER, note="try").status_code == 403
    listing = client.get("/api/v1/responses", headers=auth(VIEWER))
    assert listing.status_code == 200 and listing.json()["total"] == 1
    assert client.get("/api/v1/responses", headers=auth(), params={"state": "bogus"}).status_code == 422
    catalogue = client.get("/api/v1/responses/catalogue", headers=auth(VIEWER)).json()
    assert catalogue["simulated_only"] is True and len(catalogue["items"]) == 5


def test_overview_and_assets_reflect_simulated_actions(isolated_api):
    client, _ = isolated_api
    group_id = finding_id(client)
    assert client.get("/api/v1/dashboard/overview", headers=auth()).json()["counts"]["response_actions"] == 0
    action_id = request_action(client, group_id, "simulated_host_quarantine").json()["action_id"]
    change(client, action_id, "approve", ADMIN)
    change(client, action_id, "execute")
    assert client.get("/api/v1/dashboard/overview", headers=auth()).json()["counts"]["response_actions"] == 1
    assets = {a["ip_address"]: a for a in client.get("/api/v1/assets", headers=auth()).json()["items"]}
    assert assets[KNOWN]["simulated_state"] == "quarantined"
    assert assets["10.10.10.50"]["simulated_state"] == "normal"
    change(client, action_id, "rollback", note="Restore after exercise")
    assets = {a["ip_address"]: a for a in client.get("/api/v1/assets", headers=auth()).json()["items"]}
    assert assets[KNOWN]["simulated_state"] == "normal"


# ---- audit trail -------------------------------------------------------------------

def test_every_audit_entry_is_sealed_and_the_chain_verifies(isolated_api):
    client, session_factory = isolated_api
    group_id = finding_id(client)
    action_id = request_action(client, group_id, "simulated_connection_block").json()["action_id"]
    change(client, action_id, "approve", ADMIN)
    change(client, action_id, "execute")
    result = client.get("/api/v1/audit/verify", headers=auth()).json()
    assert result["valid"] is True, result
    assert result["total_entries"] == result["sealed_entries"] == result["checked"] >= 20
    assert result["entries_not_covered"] == 0 and len(result["latest_hash"]) == 64
    with session_factory() as session:
        assert len(session.scalars(select(AuditSealRecord)).all()) == result["total_entries"]

    listing = client.get("/api/v1/audit", headers=auth(), params={"action": "response_execute"}).json()
    assert listing["total"] == 1 and listing["items"][0]["details"]["to_state"] == "executed_in_simulation"
    assert {"analysis_run", "telemetry_ingested", "response_requested"} <= set(listing["actions"])
    assert client.get("/api/v1/audit", headers=auth(VIEWER)).status_code == 403
    assert client.get("/api/v1/audit/verify").status_code == 401


def test_modified_audit_entry_is_detected(isolated_api):
    client, session_factory = isolated_api
    finding_id(client)
    with session_factory() as session:
        entry = session.scalars(select(AuditLogRecord).where(AuditLogRecord.action == "analysis_run")).one()
        tampered_id = entry.audit_id
        entry.actor = "someone-else"
        session.commit()
    result = client.get("/api/v1/audit/verify", headers=auth()).json()
    assert result["valid"] is False and result["first_invalid_audit_id"] == tampered_id
    assert "content" in result["reason"]


def test_removed_audit_entries_are_detected(isolated_api):
    client, session_factory = isolated_api
    finding_id(client)
    with session_factory() as session:
        rows = session.scalars(select(AuditLogRecord).order_by(AuditLogRecord.audit_id)).all()
        removed_id = rows[4].audit_id
        session.delete(rows[4])
        session.commit()
    result = client.get("/api/v1/audit/verify", headers=auth()).json()
    assert result["valid"] is False and result["first_invalid_audit_id"] == removed_id
    assert "missing" in result["reason"]

    with session_factory() as session:                    # remove the entry and its seal together
        seal = session.get(AuditSealRecord, removed_id)
        session.delete(seal)
        session.commit()
    result = client.get("/api/v1/audit/verify", headers=auth()).json()
    assert result["valid"] is False and result["first_invalid_audit_id"] == removed_id + 1
    assert "link" in result["reason"]


def test_entry_without_a_seal_inside_the_chain_is_detected(isolated_api):
    client, session_factory = isolated_api
    finding_id(client)
    with session_factory() as session:
        last = session.scalars(select(AuditSealRecord).order_by(AuditSealRecord.audit_id.desc())).first()
        unsealed_id = last.audit_id
        session.delete(last)
        session.commit()
    result = client.get("/api/v1/audit/verify", headers=auth()).json()
    assert result["valid"] is False and result["first_invalid_audit_id"] == unsealed_id
    assert "no seal" in result["reason"]


# ---- demo lab ----------------------------------------------------------------------

def test_scenarios_are_listed_with_provenance_and_expectations(isolated_api):
    client, _ = isolated_api
    body = client.get("/api/v1/demo/scenarios", headers=auth(VIEWER)).json()
    assert body["data_provenance"] == "Synthetic generated data" and len(body["items"]) == 8
    for item in body["items"]:
        assert item["last_run"] is None and item["ground_truth"] in ("benign", "malicious")
        assert set(item["expected"]) == {"rules", "finding", "decision"}


@pytest.mark.parametrize("scenario_id", sorted(scenarios.SCENARIOS))
def test_scenario_runs_through_the_real_pipeline_and_meets_its_expectation(isolated_api, scenario_id):
    client, session_factory = isolated_api
    response = client.post(f"/api/v1/demo/scenarios/{scenario_id}/run", headers=auth())
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["comparison"]["matches_expected"], body["comparison"]
    assert body["events_ingested"] > 0 and body["run_id"].startswith(scenario_id)

    with session_factory() as session:                    # the events really were ingested
        stored = [a for a in session.scalars(select(AlertRecord)).all()
                  if (a.telemetry_json.get("lab_metadata") or {}).get("run_id") == body["run_id"]]
    assert len(stored) == body["events_ingested"]

    findings = client.get("/api/v1/findings", headers=auth()).json()["items"]
    if body["finding"] is None:
        assert findings == []
    else:
        assert [f["group_id"] for f in findings] == [body["finding"]["group_id"]]
        assert findings[0]["scope"] == body["run_id"]
    listed = client.get("/api/v1/demo/scenarios", headers=auth()).json()["items"]
    last = next(item for item in listed if item["scenario_id"] == scenario_id)["last_run"]
    assert last["run_id"] == body["run_id"]


def test_exfiltration_scenario_carries_byte_counts_through_ingestion(isolated_api):
    client, session_factory = isolated_api
    body = client.post("/api/v1/demo/scenarios/potential_exfiltration/run", headers=auth()).json()
    with session_factory() as session:
        sizes = [a.telemetry_json.get("bytes_out") for a in session.scalars(select(AlertRecord)).all()
                 if (a.telemetry_json.get("lab_metadata") or {}).get("run_id") == body["run_id"]]
    assert sizes and all(size == 10 * 1024 * 1024 for size in sizes)
    assert body["finding"]["decision"] != "deny"


def test_lab_runs_stay_out_of_the_global_analysis(isolated_api):
    client, _ = isolated_api
    client.post("/api/v1/demo/scenarios/port_scan/run", headers=auth())
    summary = client.post("/api/v1/analysis/run", headers=auth()).json()
    assert summary["scope"] == "all-events" and summary["events_analysed"] == 0
    assert client.get("/api/v1/findings", headers=auth()).json()["total"] == 1     # only the lab run's own


def test_demo_permissions_and_audit(isolated_api):
    client, session_factory = isolated_api
    assert client.post("/api/v1/demo/scenarios/port_scan/run").status_code == 401
    assert client.post("/api/v1/demo/scenarios/port_scan/run", headers=auth(VIEWER)).status_code == 403
    assert client.post("/api/v1/demo/scenarios/no_such/run", headers=auth()).status_code == 404
    assert client.post("/api/v1/demo/scenarios/normal_traffic/run", headers=auth(ADMIN)).status_code == 201
    runs = client.get("/api/v1/demo/runs", headers=auth(VIEWER)).json()
    assert runs["total"] == 1 and runs["items"][0]["started_by"] == "test-security_admin"
    with session_factory() as session:
        (entry,) = session.scalars(
            select(AuditLogRecord).where(AuditLogRecord.action == "demo_scenario_run")).all()
    assert entry.details_json["scenario_id"] == "normal_traffic"
