"""Versioned API for the analysis core: run analysis, detections, findings."""
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis_models import DetectionRecord, FindingRecord
from app.analysis_service import run_analysis
from app.database import get_db
from security import require_roles

router = APIRouter(prefix="/api/v1", tags=["analysis"])

READ_ROLES = ("soc_analyst", "security_admin", "viewer")
ANALYST_ROLES = ("soc_analyst", "security_admin")
SEVERITIES = ("low", "medium", "high", "critical")
RUN_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]*$"


class AnalysisRunRequest(BaseModel):
    run_id: str | None = Field(default=None, min_length=1, max_length=100, pattern=RUN_ID_PATTERN)


def _iso(value: datetime) -> str:
    if value.tzinfo is None:          # SQLite returns naive values; they were stored as UTC
        value = value.replace(tzinfo=UTC)
    return value.isoformat()


def _detection(row: DetectionRecord) -> dict[str, Any]:
    return {**row.detail_json, "group_id": row.group_id, "scope": row.scope,
            "is_current": row.is_current, "created_at": _iso(row.created_at),
            "updated_at": _iso(row.updated_at)}


def _finding(row: FindingRecord, detections: list[DetectionRecord] | None = None) -> dict[str, Any]:
    detail = row.detail_json
    body = {
        "group_id": row.group_id, "finding": row.finding, "source_ip": row.source_ip,
        "asset_id": row.asset_id, "window_start": _iso(row.window_start),
        "window_end": _iso(row.window_end), "risk_score": row.risk_score,
        "risk_level": row.risk_level, "detection_confidence": row.detection_confidence,
        "decision": row.decision, "scope": row.scope, "is_current": row.is_current,
        "categories": detail["group"]["categories"], "explanation": detail["group"]["explanation"],
        "created_at": _iso(row.created_at), "updated_at": _iso(row.updated_at),
    }
    if detections is not None:
        body.update({
            "baseline": detail["baseline"], "risk_assessment": detail["risk_assessment"],
            "policy_decision": detail["policy_decision"], "versions": row.versions_json,
            "detections": [_detection(d) for d in detections],
        })
    return body


@router.post("/analysis/run")
def start_analysis(
    request: AnalysisRunRequest | None = None,
    db: Session = Depends(get_db),
    identity: dict = Depends(require_roles(*ANALYST_ROLES)),
) -> dict:
    return run_analysis(db, actor=identity["username"], run_id=request.run_id if request else None)


@router.get("/detections")
def list_detections(
    severity: str | None = None,
    rule_id: str | None = Query(default=None, max_length=32),
    source_ip: str | None = Query(default=None, max_length=64),
    include_superseded: bool = False,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    identity: dict = Depends(require_roles(*READ_ROLES)),
) -> dict:
    if severity is not None and severity not in SEVERITIES:
        raise HTTPException(status_code=422, detail="Unsupported severity filter.")
    statement = select(DetectionRecord)
    if not include_superseded:
        statement = statement.where(DetectionRecord.is_current.is_(True))
    if severity:
        statement = statement.where(DetectionRecord.severity == severity)
    if rule_id:
        statement = statement.where(DetectionRecord.rule_id == rule_id)
    if source_ip:
        statement = statement.where(DetectionRecord.source_ip == source_ip)
    rows = db.scalars(statement.order_by(
        DetectionRecord.window_start.desc(), DetectionRecord.detection_id)).all()
    return {"total": len(rows), "limit": limit, "offset": offset,
            "items": [_detection(row) for row in rows[offset:offset + limit]]}


@router.get("/detections/{detection_id}")
def get_detection(
    detection_id: str,
    db: Session = Depends(get_db),
    identity: dict = Depends(require_roles(*READ_ROLES)),
) -> dict:
    row = db.get(DetectionRecord, detection_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Detection not found.")
    return _detection(row)


@router.get("/findings")
def list_findings(
    decision: str | None = Query(default=None, max_length=32),
    min_risk: int = Query(default=0, ge=0, le=100),
    include_superseded: bool = False,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    identity: dict = Depends(require_roles(*READ_ROLES)),
) -> dict:
    statement = select(FindingRecord).where(FindingRecord.risk_score >= min_risk)
    if not include_superseded:
        statement = statement.where(FindingRecord.is_current.is_(True))
    if decision:
        statement = statement.where(FindingRecord.decision == decision)
    rows = db.scalars(statement.order_by(
        FindingRecord.risk_score.desc(), FindingRecord.group_id)).all()
    return {"total": len(rows), "limit": limit, "offset": offset,
            "items": [_finding(row) for row in rows[offset:offset + limit]]}


@router.get("/findings/{group_id}")
def get_finding(
    group_id: str,
    db: Session = Depends(get_db),
    identity: dict = Depends(require_roles(*READ_ROLES)),
) -> dict:
    row = db.get(FindingRecord, group_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    detections = db.scalars(
        select(DetectionRecord).where(DetectionRecord.group_id == group_id)
        .order_by(DetectionRecord.window_start, DetectionRecord.detection_id)).all()
    return _finding(row, list(detections))
