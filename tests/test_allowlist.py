"""Approved-activity allowlist: core matching, pipeline effect and API."""
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core_helpers import T0, ev

sys.path.append(str(Path(__file__).resolve().parents[1] / "backend"))

import app.main as api  # noqa: E402
from app.core.allowlist import AllowEntry, apply_allowlist  # noqa: E402
from app.core.detection import DetectionEngine  # noqa: E402
from app.core.pipeline import analyse  # noqa: E402
from app.database import Base, get_db  # noqa: E402
from security import create_access_token  # noqa: E402

SOURCE = "10.10.10.50"


def sweep(hosts, port=445):
    return [ev(3 * n, SOURCE, f"10.10.10.{110 + n}", port) for n in range(hosts)]


def backup_entry(**changes):
    values = dict(entry_id="AL-1", source_ip=SOURCE, destinations=("10.10.10.96/27",),
                  categories=("destination_scan",), reason="Nightly backup job.", ports=(445,))
    values.update(changes)
    return AllowEntry(**values)


def test_entry_validation():
    with pytest.raises(ValueError):
        backup_entry(categories=("ids_alert",))                   # signature alerts are never allowlisted
    with pytest.raises(ValueError):
        backup_entry(destinations=("10.0.0.0/8",))                 # too wide
    with pytest.raises(ValueError):
        backup_entry(source_ip="not-an-ip")
    with pytest.raises(ValueError):
        backup_entry(reason="  ")
    with pytest.raises(ValueError):
        backup_entry(ports=(70000,))


def test_fully_covered_detection_is_suppressed_not_dropped():
    events = sweep(14)
    detections = DetectionEngine().run(events)
    assert any(d.category == "destination_scan" for d in detections)
    kept, suppressed = apply_allowlist(detections, events, [backup_entry()])
    assert not any(d.category == "destination_scan" for d in kept)
    assert suppressed and suppressed[0].entry_id == "AL-1" and suppressed[0].reason


@pytest.mark.parametrize("extra", [
    ("10.10.10.200", 445),     # one host outside the approved range
    ("10.10.10.111", 3389),    # an approved host on a port that is not approved
])
def test_one_uncovered_event_keeps_the_whole_detection(extra):
    events = sweep(14) + [ev(1, SOURCE, extra[0], extra[1])]
    kept, suppressed = apply_allowlist(DetectionEngine().run(events), events, [backup_entry()])
    assert any(d.category == "destination_scan" for d in kept) and not suppressed


def test_entry_only_covers_its_own_source_and_category():
    other = [ev(3 * i, "10.10.10.25", f"10.10.10.{110 + i}", 445) for i in range(14)]
    kept, suppressed = apply_allowlist(DetectionEngine().run(other), other, [backup_entry()])
    assert kept and not suppressed
    events = sweep(14)
    kept, suppressed = apply_allowlist(DetectionEngine().run(events), events,
                                       [backup_entry(categories=("port_scan",))])
    assert kept and not suppressed


def test_pipeline_reports_suppressions_and_version():
    result = analyse(sweep(14), allowlist=[backup_entry()])
    assert not result.findings and len(result.suppressed) >= 1
    assert result.versions["allowlist"] == "allowlist-1.0"
    assert analyse(sweep(14)).versions["allowlist"] == "none"


# ---- API ------------------------------------------------------------------------

@pytest.fixture()
def client(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{(tmp_path / 'allowlist.db').as_posix()}",
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)

    def override():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    previous = api.app.dependency_overrides.copy()
    monkeypatch.setattr(api, "engine", engine)
    api.app.dependency_overrides[get_db] = override
    try:
        with TestClient(api.app) as test_client:
            yield test_client
    finally:
        api.app.dependency_overrides.clear()
        api.app.dependency_overrides.update(previous)
        engine.dispose()


def auth(role):
    return {"Authorization": f"Bearer {create_access_token(username=f'test-{role}', role=role)}"}


BODY = {"source_ip": SOURCE, "destinations": ["10.10.10.96/27"], "ports": [445],
        "categories": ["destination_scan"], "reason": "Nightly backup job to the file servers."}


def test_api_roles_create_list_disable(client):
    assert client.post("/api/v1/allowlist", json=BODY, headers=auth("soc_analyst")).status_code == 403
    created = client.post("/api/v1/allowlist", json=BODY, headers=auth("security_admin"))
    assert created.status_code == 201, created.text
    entry = created.json()
    assert entry["entry_id"].startswith("AL-") and entry["active"] is True
    listed = client.get("/api/v1/allowlist", headers=auth("viewer")).json()
    assert [e["entry_id"] for e in listed["items"]] == [entry["entry_id"]]
    assert "ids_alert" not in listed["categories"]
    path = f"/api/v1/allowlist/{entry['entry_id']}/disable"
    assert client.post(path, json={"note": ""}, headers=auth("security_admin")).status_code == 422
    done = client.post(path, json={"note": "Backup job retired."}, headers=auth("security_admin"))
    assert done.status_code == 200 and done.json()["active"] is False
    assert client.post(path, json={"note": "again"}, headers=auth("security_admin")).status_code == 409
    assert client.post("/api/v1/allowlist/AL-missing/disable", json={"note": "x y z"},
                       headers=auth("security_admin")).status_code == 404


@pytest.mark.parametrize("change", [{"categories": ["ids_alert"]}, {"destinations": ["10.0.0.0/8"]},
                                    {"source_ip": "nope"}, {"categories": []}])
def test_api_rejects_unsafe_entries(client, change):
    response = client.post("/api/v1/allowlist", json={**BODY, **change}, headers=auth("security_admin"))
    assert response.status_code == 422


def test_analysis_run_uses_active_entries(client):
    for i in range(14):
        raw = {"event_type": "flow", "timestamp": (T0 + timedelta(seconds=3 * i)).isoformat(),
               "src_ip": SOURCE, "dest_ip": f"10.10.10.{110 + i}", "dest_port": 445, "proto": "TCP",
               "flow": {"bytes_toserver": 900, "bytes_toclient": 100}}
        assert client.post("/v1/telemetry/events", json=raw, headers=auth("ingestor")).status_code == 200
    first = client.post("/api/v1/analysis/run", headers=auth("soc_analyst")).json()
    assert first["finding_count"] >= 1 and first["suppressed_count"] == 0
    entry = client.post("/api/v1/allowlist", json=BODY, headers=auth("security_admin")).json()
    second = client.post("/api/v1/analysis/run", headers=auth("soc_analyst")).json()
    assert second["finding_count"] == 0 and second["suppressed_count"] >= 1
    assert second["suppressed"][0]["entry_id"] == entry["entry_id"]
    client.post(f"/api/v1/allowlist/{entry['entry_id']}/disable", json={"note": "Retired."},
                headers=auth("security_admin"))
    third = client.post("/api/v1/analysis/run", headers=auth("soc_analyst")).json()
    assert third["finding_count"] >= 1 and third["suppressed_count"] == 0
