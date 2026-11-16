"""File import, comparative evaluation and CSV reports."""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

sys.path.append(str(Path(__file__).resolve().parents[1] / "backend"))

import app.main as api
from app.analysis_service import asset_contexts
from app.api_ingest import parse_records
from app.db_models import AlertRecord, AuditLogRecord
from app.evaluation import run_evaluation
from security import create_access_token

T0 = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)


def auth(role="security_admin"):
    return {"Authorization": f"Bearer {create_access_token(username=f'test-{role}', role=role)}"}


@pytest.fixture
def isolated_api(tmp_path, monkeypatch):
    test_engine = create_engine(f"sqlite:///{(tmp_path / 'ingest_test.db').as_posix()}",
                                connect_args={"check_same_thread": False})
    session_factory = sessionmaker(bind=test_engine)

    def override_get_db():
        with session_factory() as session:
            yield session

    previous = api.app.dependency_overrides.copy()
    monkeypatch.setattr(api, "engine", test_engine)
    api.app.dependency_overrides[api.get_db] = override_get_db
    try:
        with TestClient(api.app) as client:
            yield client, session_factory
    finally:
        api.app.dependency_overrides.clear()
        api.app.dependency_overrides.update(previous)
        test_engine.dispose()


def suricata_flow(i, src="10.10.10.25", port=None):
    return {"timestamp": (T0 + timedelta(seconds=i)).isoformat(), "event_type": "flow", "src_ip": src,
            "src_port": 40000 + i, "dest_ip": "10.10.10.80", "dest_port": port or 1000 + i, "proto": "TCP",
            "flow": {"bytes_toserver": 60, "bytes_toclient": 0}}


def zeek_conn(i, src="10.10.10.50"):
    return {"_path": "conn", "ts": (T0 + timedelta(seconds=i)).timestamp(), "uid": f"C{i}",
            "id.orig_h": src, "id.orig_p": 50000 + i, "id.resp_h": "198.51.100.9", "id.resp_p": 443,
            "proto": "tcp", "orig_bytes": 1500, "resp_bytes": 9000}


def upload(client, text, name="eve.json", role="security_admin", analyse=True):
    return client.post("/api/v1/ingest/upload", headers=auth(role),
                       files={"file": (name, text.encode("utf-8"), "application/json")},
                       data={"analyse": "true" if analyse else "false"})


def lines(records):
    return "\n".join(json.dumps(r) for r in records) + "\n"


# ---- import -------------------------------------------------------------------

def test_suricata_eve_lines_are_imported_and_analysed(isolated_api):
    client, session_factory = isolated_api
    response = upload(client, lines([suricata_flow(i) for i in range(20)]))
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["records_read"] == 20 and body["stored"] == 20 and body["rejected"] == 0
    assert body["by_sensor"] == {"suricata": 20}
    assert body["analysis"]["detection_count"] == 1 and body["analysis"]["finding_count"] == 1
    with session_factory() as session:
        stored = session.scalars(select(AlertRecord)).all()
        assert len(stored) == 20 and stored[0].telemetry_json["bytes_out"] == 60
        actions = [r.action for r in session.scalars(select(AuditLogRecord)).all()]
    assert "telemetry_imported" in actions and "analysis_run" in actions


def test_zeek_json_conn_log_keeps_bytes_and_connection_type(isolated_api):
    client, session_factory = isolated_api
    body = upload(client, lines([zeek_conn(i) for i in range(5)]), "conn.log", analyse=False).json()
    assert body["stored"] == 5 and body["by_sensor"] == {"zeek": 5} and body["analysis"] is None
    with session_factory() as session:
        telemetry = session.scalars(select(AlertRecord)).first().telemetry_json
    assert telemetry["event_type"] == "connection" and telemetry["bytes_out"] == 1500
    assert telemetry["bytes_in"] == 9000 and telemetry["destination_port"] == 443


def test_json_array_files_are_accepted(isolated_api):
    client, _ = isolated_api
    body = upload(client, json.dumps([suricata_flow(i) for i in range(3)]), analyse=False).json()
    assert body["stored"] == 3


def test_reimporting_the_same_records_skips_duplicates(isolated_api):
    client, session_factory = isolated_api
    text = lines([suricata_flow(i) for i in range(4)])
    upload(client, text, analyse=False)
    second = upload(client, text + json.dumps(suricata_flow(4)) + "\n", analyse=False).json()
    assert second["stored"] == 1 and second["duplicates_skipped"] == 4
    with session_factory() as session:
        assert len(session.scalars(select(AlertRecord)).all()) == 5


def test_bad_records_are_rejected_with_line_numbers_and_others_kept(isolated_api):
    client, _ = isolated_api
    text = "\n".join([json.dumps(suricata_flow(0)), "{not json", json.dumps([1, 2]),
                      json.dumps({"event_type": "stats"}),
                      json.dumps({**suricata_flow(1), "timestamp": "yesterday"}),
                      json.dumps(suricata_flow(2))])
    body = upload(client, text, analyse=False).json()
    assert body["stored"] == 2 and body["rejected"] == 4
    assert [e["line"] for e in body["errors"]] == [2, 3, 4, 5]
    assert body["errors"][0]["reason"] == "Line is not valid JSON."


ZEEK_HEADER = "\n".join([
    "#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-", "#path\tconn",
    "#open\t2026-11-16-10-00-00",
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration"
    "\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\ttunnel_parents",
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring"
    "\tbool\tset[string]",
])


def zeek_tsv_row(i, src="10.10.10.25", port=None):
    port = port if port is not None else 20 + i * 7
    return "\t".join([f"{1794823200 + i}.250000", f"C{i:04d}", src, "51000", "10.10.10.80", str(port), "tcp",
                      "-", "0.001", "60", "0", "S0", "T", "(empty)"])


def test_zeek_tsv_is_parsed_like_zeek_json():
    text = ZEEK_HEADER + "\n" + zeek_tsv_row(0) + "\n#close\t2026-11-16-10-05-00\n"
    records, errors = parse_records(text)
    assert errors == [] and len(records) == 1
    line, record = records[0]
    assert line == 9 and record["_path"] == "conn" and record["id.orig_h"] == "10.10.10.25"
    assert record["id.resp_p"] == 20 and record["orig_bytes"] == 60 and record["ts"] == 1794823200.25
    assert record["local_orig"] is True and record["tunnel_parents"] == [] and "service" not in record


def test_zeek_tsv_rows_with_wrong_field_count_are_reported():
    text = ZEEK_HEADER + "\n" + zeek_tsv_row(0) + "\nonly\tthree\tfields\n" + zeek_tsv_row(1) + "\n"
    records, errors = parse_records(text)
    assert len(records) == 2 and errors == [{"line": 10, "reason": "Expected 14 fields, found 3."}]
    assert parse_records("#separator \\x09\n1\t2\n")[1][0]["reason"] == "Record before the #fields header."


def test_zeek_tsv_conn_log_import_detects_a_port_scan(isolated_api):
    client, _ = isolated_api
    text = ZEEK_HEADER + "\n" + "\n".join(zeek_tsv_row(i) for i in range(25)) + "\n"
    body = upload(client, text, "conn.log", analyse=True).json()
    assert body["stored"] == 25 and body["rejected"] == 0, body
    assert body["analysis"]["detections_by_rule"].get("DET-001") == 1


@pytest.mark.parametrize("content,status", [("", 422), ("   \n", 422), ("\xff", 422)])
def test_empty_or_binary_files_are_rejected(isolated_api, content, status):
    client, _ = isolated_api
    data = content.encode("latin-1")
    response = client.post("/api/v1/ingest/upload", headers=auth(),
                           files={"file": ("x.json", data, "application/json")})
    assert response.status_code == status


def test_oversized_file_is_rejected(isolated_api, monkeypatch):
    client, _ = isolated_api
    import app.api_ingest as ingest
    monkeypatch.setattr(ingest, "MAX_FILE_BYTES", 100)
    assert upload(client, lines([suricata_flow(i) for i in range(5)])).status_code == 413


def test_import_requires_ingestor_or_administrator(isolated_api):
    client, _ = isolated_api
    text = lines([suricata_flow(0)])
    assert client.post("/api/v1/ingest/upload", files={"file": ("a", b"{}")}).status_code == 401
    for role in ("soc_analyst", "viewer"):
        assert upload(client, text, role=role).status_code == 403
    assert upload(client, text, role="ingestor", analyse=False).status_code == 201
    listing = client.get("/api/v1/ingest/imports", headers=auth("soc_analyst")).json()
    assert listing["total"] == 1 and listing["items"][0]["filename"] == "eve.json"


def test_uploaded_filename_cannot_carry_a_path(isolated_api):
    client, _ = isolated_api
    body = upload(client, lines([suricata_flow(0)]), name="..\\..\\evil/../eve.json", analyse=False).json()
    assert body["filename"] == "eve.json"


# ---- evaluation ----------------------------------------------------------------

def test_evaluation_is_reproducible_and_labelled():
    first = run_evaluation(asset_contexts(), variants=2)
    second = run_evaluation(asset_contexts(), variants=2)
    assert first["metrics"] == second["metrics"]
    assert first["case_count"] == 26 and first["malicious_cases"] == 16 and first["benign_cases"] == 10
    assert first["data_provenance"] == "Synthetic generated data" and first["limitations"]
    for row in first["metrics"]:
        assert row["true_positives"] + row["false_negatives"] == 16
        assert row["false_positives"] + row["true_negatives"] == 10


def test_evaluation_shows_the_trade_offs_between_approaches():
    result = run_evaluation(asset_contexts(), variants=1)
    family = {row["family"]: row for row in result["by_family"]}
    assert family["slow_port_scan"]["rule_based"] == 0 and family["slow_port_scan"]["anomaly_based"] == 1
    assert family["beacon"]["rule_based"] == 1 and family["beacon"]["anomaly_based"] == 0
    assert family["unknown_device_scan"]["anomaly_based"] == 0          # no history, no baseline
    assert family["normal_browsing"] == {**family["normal_browsing"],
                                         "rule_based": 0, "anomaly_based": 0, "combined": 0}
    with pytest.raises(ValueError):
        run_evaluation(asset_contexts(), variants=0)


def test_evaluation_reports_the_allowlist_gain_and_its_cost():
    result = run_evaluation(asset_contexts(), variants=1)
    comparison = result["allowlist_comparison"]
    before = {f["family"]: f for f in result["by_family"]}
    after = {f["family"]: f for f in comparison["by_family"]}
    for benign in ("backup_job", "cloud_backup"):                     # look-alikes no longer flagged
        assert before[benign]["rule_based"] == 1 and after[benign]["rule_based"] == 0
    abuse = "backup_path_exfiltration"                                # the cost: an abused approved path
    assert before[abuse]["combined"] == 1 and after[abuse]["combined"] == 0
    for family in ("port_scan", "destination_scan", "exfiltration", "beacon", "multi_stage"):
        assert after[family] == before[family]                        # other attacks are untouched
    changed = {c["family"] for c in comparison["changed_cases"]}
    assert abuse in changed and "port_scan" not in changed


def test_evaluation_api_stores_and_returns_latest(isolated_api):
    client, _ = isolated_api
    assert client.get("/api/v1/demo/evaluation/latest", headers=auth("viewer")).status_code == 404
    assert client.post("/api/v1/demo/evaluation", headers=auth("viewer")).status_code == 403
    created = client.post("/api/v1/demo/evaluation", headers=auth("soc_analyst"), params={"variants": 1})
    assert created.status_code == 201, created.text
    latest = client.get("/api/v1/demo/evaluation/latest", headers=auth("viewer")).json()
    assert latest["run_id"] == created.json()["run_id"] and len(latest["metrics"]) == 3
    report = client.get("/api/v1/reports/evaluation.csv", headers=auth("viewer"))
    assert report.status_code == 200 and report.text.startswith("case_id,family,label")
    assert len(report.text.strip().splitlines()) == 1 + 13


# ---- reports -------------------------------------------------------------------

def test_findings_and_audit_csv(isolated_api):
    client, _ = isolated_api
    upload(client, lines([suricata_flow(i) for i in range(20)]))
    findings = client.get("/api/v1/reports/findings.csv", headers=auth("viewer"))
    assert findings.status_code == 200 and "attachment" in findings.headers["content-disposition"]
    rows = findings.text.strip().splitlines()
    assert rows[0].startswith("group_id,finding,source_ip") and len(rows) == 2 and ",port_scan," in rows[1]
    assert client.get("/api/v1/reports/audit.csv", headers=auth("viewer")).status_code == 403
    audit = client.get("/api/v1/reports/audit.csv", headers=auth("soc_analyst"))
    assert audit.status_code == 200 and "telemetry_imported" in audit.text


def test_csv_neutralises_formulas():
    from app.api_reports import _cell
    assert _cell("=HYPERLINK(1)") == "'=HYPERLINK(1)" and _cell("10.0.0.1") == "10.0.0.1" and _cell(5) == 5
