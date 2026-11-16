"""Telemetry file import (AG-03, AG-04): Suricata EVE JSON and Zeek JSON logs.

Both sensors write one JSON object per line, so a file is read line by line.
A JSON array of objects is also accepted. Every record goes through the same
``process_and_store`` path as the single-event API. Input is untrusted: a bad
record is rejected with its line number and does not stop the others.
"""
import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis_service import run_analysis
from app.database import get_db
from app.db_models import AuditLogRecord
from app.platform_models import EventFingerprintRecord, TelemetryImportRecord
from security import require_roles

router = APIRouter(prefix="/api/v1", tags=["ingestion"])

IMPORT_ROLES = ("ingestor", "security_admin")
READ_ROLES = ("soc_analyst", "security_admin", "viewer", "ingestor")
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_RECORDS = 20_000
MAX_RECORD_BYTES = 64 * 1024
MAX_REPORTED_ERRORS = 50


from app.zeek_tsv import looks_like_zeek_tsv, parse_zeek_tsv  # noqa: E402


def fingerprint(raw: dict[str, Any]) -> str:
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def parse_records(text: str) -> tuple[list[tuple[int, dict[str, Any]]], list[dict[str, Any]]]:
    """Return ([(line, record)], [errors]). Never raises for bad content."""
    errors: list[dict[str, Any]] = []
    stripped = text.lstrip()

    if looks_like_zeek_tsv(text):
        return parse_zeek_tsv(text, MAX_RECORD_BYTES)

    if stripped.startswith("["):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as error:
            return [], [{"line": error.lineno, "reason": "The file is not valid JSON."}]
        if not isinstance(data, list):
            return [], [{"line": 1, "reason": "A JSON file must contain an array of records."}]
        records = []
        for index, item in enumerate(data, start=1):
            if isinstance(item, dict):
                records.append((index, item))
            else:
                errors.append({"line": index, "reason": "Array item is not a JSON object."})
        return records, errors

    records = []
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            if not errors or errors[-1]["reason"] != ZEEK_TSV:
                errors.append({"line": number, "reason": ZEEK_TSV})
            continue
        if len(line.encode("utf-8")) > MAX_RECORD_BYTES:
            errors.append({"line": number, "reason": "Record is larger than 64 KB."})
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            errors.append({"line": number, "reason": "Line is not valid JSON."})
            continue
        if not isinstance(item, dict):
            errors.append({"line": number, "reason": "Line is not a JSON object."})
            continue
        records.append((number, item))
    return records, errors


ZEEK_TSV = ("Header line ignored. A Zeek tab-separated log must start with its "
            "#separator or #fields header; JSON lines need no header.")


def _iso(value: datetime) -> str:
    return (value if value.tzinfo else value.replace(tzinfo=UTC)).isoformat()


def _import(row: TelemetryImportRecord) -> dict[str, Any]:
    return {"import_id": row.import_id, "filename": row.filename, "sha256": row.sha256,
            "size_bytes": row.size_bytes, "imported_by": row.imported_by,
            "imported_at": _iso(row.imported_at), **row.result_json}


@router.post("/ingest/upload", status_code=201)
async def upload_telemetry(
    file: UploadFile = File(...),
    analyse: bool = Form(default=True),
    db: Session = Depends(get_db),
    identity: dict = Depends(require_roles(*IMPORT_ROLES)),
) -> dict:
    from app.main import process_and_store          # shared ingestion path (avoids a circular import)

    content = await file.read(MAX_FILE_BYTES + 1)
    if len(content) > MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail="The file is larger than 10 MB.")
    if not content.strip():
        raise HTTPException(status_code=422, detail="The file is empty.")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise HTTPException(status_code=422, detail="The file is not UTF-8 text.") from error

    records, errors = parse_records(text)
    if len(records) > MAX_RECORDS:
        raise HTTPException(status_code=413, detail=f"The file has more than {MAX_RECORDS} records.")

    import_id = uuid4().hex
    filename = (file.filename or "upload").replace("\\", "/").split("/")[-1][:255] or "upload"
    stored = duplicates = unresolved = 0
    by_sensor: dict[str, int] = {}
    seen_in_file: set[str] = set()

    for line, raw in records:
        digest = fingerprint(raw)
        if digest in seen_in_file or db.get(EventFingerprintRecord, digest) is not None:
            duplicates += 1
            continue
        try:
            result = process_and_store(raw, db, commit=False)
        except HTTPException as error:
            errors.append({"line": line, "reason": str(error.detail)})
            continue
        except (ValueError, TypeError) as error:
            errors.append({"line": line, "reason": str(error) or "Invalid record."})
            continue
        seen_in_file.add(digest)
        db.add(EventFingerprintRecord(fingerprint=digest, event_id=result["event_id"], import_id=import_id))
        stored += 1
        sensor = result["telemetry"]["source"]
        by_sensor[sensor] = by_sensor.get(sensor, 0) + 1
        if result["status"] == "unresolved_asset":
            unresolved += 1

    errors.sort(key=lambda item: item["line"])
    result = {
        "records_read": len(records), "stored": stored, "duplicates_skipped": duplicates,
        "rejected": len(errors), "unresolved_sources": unresolved, "by_sensor": by_sensor,
        "errors": errors[:MAX_REPORTED_ERRORS], "errors_truncated": len(errors) > MAX_REPORTED_ERRORS,
        "analysis": None,
    }
    now = datetime.now(UTC)
    row = TelemetryImportRecord(import_id=import_id, filename=filename,
                                sha256=hashlib.sha256(content).hexdigest(), size_bytes=len(content),
                                imported_by=identity["username"], imported_at=now, result_json=result)
    db.add(row)
    db.add(AuditLogRecord(occurred_at=now, actor=identity["username"][:128], action="telemetry_imported",
                          target_type="telemetry_import", target_id=import_id, details_json={
                              "filename": filename, "sha256": row.sha256, "stored": stored,
                              "duplicates_skipped": duplicates, "rejected": len(errors)}))
    db.commit()

    if analyse and stored:
        summary = run_analysis(db, actor=identity["username"])
        row.result_json = {**result, "analysis": {
            key: summary[key] for key in ("events_analysed", "detection_count", "finding_count", "suppressed_count",
                                           "detections_by_rule", "completed_at")}}
        db.commit()
    return _import(row)


@router.get("/ingest/imports")
def list_imports(db: Session = Depends(get_db),
                 identity: dict = Depends(require_roles(*READ_ROLES))) -> dict:
    rows = db.scalars(select(TelemetryImportRecord)
                      .order_by(TelemetryImportRecord.imported_at.desc()).limit(50)).all()
    return {"total": len(rows), "items": [_import(row) for row in rows]}
