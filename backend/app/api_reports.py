"""Detection evaluation and CSV reports under /api/v1."""
import csv
import io
import secrets
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis_models import FindingRecord
from app.analysis_service import asset_contexts
from app.database import get_db
from app.db_models import AuditLogRecord
from app.evaluation import run_evaluation
from app.platform_models import DemoRunRecord
from security import require_roles

router = APIRouter(prefix="/api/v1", tags=["reports"])

READ_ROLES = ("soc_analyst", "security_admin", "viewer")
ANALYST_ROLES = ("soc_analyst", "security_admin")
EVALUATION_SCENARIO = "evaluation"


def _iso(value: datetime) -> str:
    return (value if value.tzinfo else value.replace(tzinfo=UTC)).isoformat()


def _cell(value: Any) -> Any:
    """Neutralise spreadsheet formulas in exported text (CSV injection)."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def _csv(filename: str, header: list[str], rows: list[list[Any]]) -> Response:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    writer.writerows([[_cell(value) for value in row] for row in rows])
    return Response(buffer.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.post("/demo/evaluation", status_code=201)
def evaluate(
    variants: int = Query(default=5, ge=1, le=10),
    db: Session = Depends(get_db),
    identity: dict = Depends(require_roles(*ANALYST_ROLES)),
) -> dict:
    started_at = datetime.now(UTC)
    result = run_evaluation(asset_contexts(), variants)
    run_id = f"{EVALUATION_SCENARIO}-{started_at:%Y%m%d%H%M%S}-{secrets.token_hex(2)}"
    db.add(DemoRunRecord(run_id=run_id, scenario_id=EVALUATION_SCENARIO, started_by=identity["username"],
                         started_at=started_at, result_json=result))
    db.add(AuditLogRecord(occurred_at=started_at, actor=identity["username"][:128], action="evaluation_run",
                          target_type="demo_run", target_id=run_id, details_json={
                              "evaluation_version": result["evaluation_version"],
                              "case_count": result["case_count"],
                              "metrics": {m["approach"]: {k: m[k] for k in ("precision", "recall",
                                          "false_positive_rate")} for m in result["metrics"]}}))
    db.commit()
    return {"run_id": run_id, "started_by": identity["username"], "started_at": started_at.isoformat(), **result}


@router.get("/demo/evaluation/latest")
def latest_evaluation(db: Session = Depends(get_db),
                      identity: dict = Depends(require_roles(*READ_ROLES))) -> dict:
    row = db.scalars(select(DemoRunRecord).where(DemoRunRecord.scenario_id == EVALUATION_SCENARIO)
                     .order_by(DemoRunRecord.started_at.desc()).limit(1)).first()
    if row is None:
        raise HTTPException(status_code=404, detail="No evaluation has been run yet.")
    return {"run_id": row.run_id, "started_by": row.started_by, "started_at": _iso(row.started_at),
            **row.result_json}


@router.get("/reports/findings.csv")
def findings_csv(include_superseded: bool = False, db: Session = Depends(get_db),
                 identity: dict = Depends(require_roles(*READ_ROLES))) -> Response:
    statement = select(FindingRecord)
    if not include_superseded:
        statement = statement.where(FindingRecord.is_current.is_(True))
    rows = db.scalars(statement.order_by(FindingRecord.risk_score.desc(), FindingRecord.group_id)).all()
    return _csv("aegisgate-findings.csv",
                ["group_id", "finding", "source_ip", "asset_id", "window_start", "window_end", "risk_score",
                 "risk_level", "detection_confidence", "decision", "categories", "is_current", "policy_version"],
                [[r.group_id, r.finding, r.source_ip, r.asset_id or "", _iso(r.window_start), _iso(r.window_end),
                  r.risk_score, r.risk_level, r.detection_confidence, r.decision,
                  ";".join(r.detail_json["group"]["categories"]), r.is_current,
                  r.detail_json["policy_decision"]["policy_version"]] for r in rows])


@router.get("/reports/audit.csv")
def audit_csv(db: Session = Depends(get_db),
              identity: dict = Depends(require_roles(*ANALYST_ROLES))) -> Response:
    rows = db.scalars(select(AuditLogRecord).order_by(AuditLogRecord.audit_id)).all()
    return _csv("aegisgate-audit.csv", ["audit_id", "occurred_at", "actor", "action", "target_type", "target_id"],
                [[r.audit_id, _iso(r.occurred_at), r.actor, r.action, r.target_type, r.target_id] for r in rows])


@router.get("/reports/evaluation.csv")
def evaluation_csv(db: Session = Depends(get_db),
                   identity: dict = Depends(require_roles(*READ_ROLES))) -> Response:
    row = db.scalars(select(DemoRunRecord).where(DemoRunRecord.scenario_id == EVALUATION_SCENARIO)
                     .order_by(DemoRunRecord.started_at.desc()).limit(1)).first()
    if row is None:
        raise HTTPException(status_code=404, detail="No evaluation has been run yet.")
    cases = row.result_json["cases"]
    return _csv("aegisgate-evaluation.csv",
                ["case_id", "family", "label", "source_ip", "events", "rule_flagged", "rules", "rule_latency_s",
                 "anomaly_flagged", "anomaly_metrics", "anomaly_latency_s", "combined_flagged",
                 "combined_decision", "combined_risk", "combined_latency_s"],
                [[c["case_id"], c["family"], c["label"], c["source_ip"], c["event_count"],
                  c["rule_based"]["flagged"], ";".join(c["rule_based"]["rules"]),
                  c["rule_based"]["latency_seconds"], c["anomaly_based"]["flagged"],
                  ";".join(c["anomaly_based"]["metrics"]), c["anomaly_based"]["latency_seconds"],
                  c["combined"]["flagged"], c["combined"]["decision"] or "", c["combined"]["risk_score"],
                  c["combined"]["latency_seconds"]] for c in cases])
