"""Simulated responses, audit trail and Demo Lab under /api/v1."""
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis_models import DetectionRecord, FindingRecord
from app.analysis_service import run_analysis
from app.audit_trail import verify_audit_trail
from app.core import scenarios
from app.core.response import (
    ACTIONS, ACTIVE_STATES, LOW_IMPACT, STATES, ResponseError, SimulationAdapter, impact_of,
    initial_state, next_state,
)
from app.database import get_db
from app.db_models import AuditLogRecord
from app.platform_models import DemoRunRecord, ResponseActionRecord
from security import require_roles

router = APIRouter(prefix="/api/v1", tags=["platform"])

READ_ROLES = ("soc_analyst", "security_admin", "viewer")
ANALYST_ROLES = ("soc_analyst", "security_admin")
ERROR_STATUS = {"unknown_action": 422, "unknown_operation": 404, "forbidden": 403, "invalid_transition": 409}
NOTE_REQUIRED = ("reject", "rollback")
adapter = SimulationAdapter()


def _iso(value: datetime) -> str:
    return (value if value.tzinfo else value.replace(tzinfo=UTC)).isoformat()


def _audit(db: Session, actor: str, action: str, target_type: str, target_id: str,
           details: dict[str, Any]) -> None:
    db.add(AuditLogRecord(occurred_at=datetime.now(UTC), actor=actor[:128], action=action,
                          target_type=target_type, target_id=target_id[:255], details_json=details))


def _fail(error: ResponseError) -> HTTPException:
    return HTTPException(status_code=ERROR_STATUS.get(error.code, 400), detail=str(error))


# ------------------------------------------------------------------ responses

class ResponseRequest(BaseModel):
    group_id: str = Field(min_length=1, max_length=64)
    action_type: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=3, max_length=2000)


class OperationRequest(BaseModel):
    note: str | None = Field(default=None, max_length=2000)


def _action(row: ResponseActionRecord) -> dict[str, Any]:
    return {
        "action_id": row.action_id, "group_id": row.group_id, "source_ip": row.source_ip,
        "asset_id": row.asset_id, "action_type": row.action_type, "impact": row.impact,
        "state": row.state, "reason": row.reason, "requested_by": row.requested_by,
        "requested_at": _iso(row.requested_at), "updated_at": _iso(row.updated_at),
        "outcome": row.outcome_json, "history": row.history_json, "simulated": True,
    }


def _apply(row: ResponseActionRecord, operation: str, identity: dict, note: str | None) -> None:
    """Move the action to its next state and record who did it."""
    new_state = next_state(row.state, operation, identity["role"])
    now = datetime.now(UTC)
    if operation == "execute":
        row.outcome_json = vars(adapter.execute(row.action_type))
    elif operation == "rollback":
        row.outcome_json = vars(adapter.rollback(row.action_type))
    row.state = new_state
    row.updated_at = now
    row.history_json = [*row.history_json, {
        "at": now.isoformat(), "by": identity["username"], "role": identity["role"],
        "operation": operation, "state": new_state, "note": note}]


@router.get("/responses/catalogue")
def response_catalogue(identity: dict = Depends(require_roles(*READ_ROLES))) -> dict:
    return {"simulated_only": True, "items": [
        {"action_type": name, "impact": impact, "effect": effect, "target_state": state,
         "requires_approval": impact != LOW_IMPACT}
        for name, (impact, effect, state) in ACTIONS.items()]}


@router.get("/responses")
def list_responses(
    state: str | None = None,
    group_id: str | None = Query(default=None, max_length=64),
    db: Session = Depends(get_db),
    identity: dict = Depends(require_roles(*READ_ROLES)),
) -> dict:
    if state is not None and state not in STATES:
        raise HTTPException(status_code=422, detail="Unsupported state filter.")
    statement = select(ResponseActionRecord)
    if state:
        statement = statement.where(ResponseActionRecord.state == state)
    if group_id:
        statement = statement.where(ResponseActionRecord.group_id == group_id)
    rows = db.scalars(statement.order_by(
        ResponseActionRecord.requested_at.desc(), ResponseActionRecord.action_id)).all()
    return {"total": len(rows), "items": [_action(row) for row in rows]}


@router.post("/responses", status_code=201)
def request_response(
    body: ResponseRequest,
    db: Session = Depends(get_db),
    identity: dict = Depends(require_roles(*ANALYST_ROLES)),
) -> dict:
    finding = db.get(FindingRecord, body.group_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    try:
        state = initial_state(body.action_type, identity["role"])
        impact = impact_of(body.action_type)
    except ResponseError as error:
        raise _fail(error) from error

    duplicate = db.scalars(select(ResponseActionRecord).where(
        ResponseActionRecord.group_id == body.group_id,
        ResponseActionRecord.action_type == body.action_type,
        ResponseActionRecord.state.in_(ACTIVE_STATES))).first()
    if duplicate is not None:
        raise HTTPException(status_code=409, detail="This action is already active for the finding.")

    now = datetime.now(UTC)
    row = ResponseActionRecord(
        action_id=uuid4().hex, group_id=finding.group_id, source_ip=finding.source_ip,
        asset_id=finding.asset_id, action_type=body.action_type, impact=impact, state=state,
        reason=body.reason, requested_by=identity["username"], requested_at=now, updated_at=now,
        outcome_json=None,
        history_json=[{"at": now.isoformat(), "by": identity["username"], "role": identity["role"],
                       "operation": "request", "state": state, "note": body.reason}])
    if impact == LOW_IMPACT:
        _apply(row, "execute", identity, None)          # low impact needs no approval
    db.add(row)
    _audit(db, identity["username"], "response_requested", "response_action", row.action_id, {
        "group_id": row.group_id, "action_type": row.action_type, "impact": impact,
        "state": row.state, "source_ip": row.source_ip, "simulated": True})
    db.commit()
    return _action(row)


@router.post("/responses/{action_id}/{operation}")
def change_response(
    action_id: str,
    operation: str,
    body: OperationRequest | None = None,
    db: Session = Depends(get_db),
    identity: dict = Depends(require_roles(*ANALYST_ROLES)),
) -> dict:
    row = db.get(ResponseActionRecord, action_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Response action not found.")
    note = (body.note or "").strip() if body else ""
    if operation in NOTE_REQUIRED and len(note) < 3:
        raise HTTPException(status_code=422, detail=f"A reason is required to {operation} an action.")
    previous = row.state
    try:
        _apply(row, operation, identity, note or None)
    except ResponseError as error:
        raise _fail(error) from error
    _audit(db, identity["username"], f"response_{operation}", "response_action", row.action_id, {
        "group_id": row.group_id, "action_type": row.action_type, "from_state": previous,
        "to_state": row.state, "note": note or None, "simulated": True})
    db.commit()
    return _action(row)


# ---------------------------------------------------------------------- audit

@router.get("/audit")
def list_audit(
    action: str | None = Query(default=None, max_length=128),
    actor: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    identity: dict = Depends(require_roles(*ANALYST_ROLES)),
) -> dict:
    statement = select(AuditLogRecord)
    if action:
        statement = statement.where(AuditLogRecord.action == action)
    if actor:
        statement = statement.where(AuditLogRecord.actor == actor)
    rows = db.scalars(statement.order_by(AuditLogRecord.audit_id.desc())).all()
    actions = sorted({name for name in db.scalars(select(AuditLogRecord.action).distinct()).all()})
    return {"total": len(rows), "limit": limit, "offset": offset, "actions": actions, "items": [
        {"audit_id": row.audit_id, "occurred_at": _iso(row.occurred_at), "actor": row.actor,
         "action": row.action, "target_type": row.target_type, "target_id": row.target_id,
         "details": row.details_json}
        for row in rows[offset:offset + limit]]}


@router.get("/audit/verify")
def verify_audit(
    db: Session = Depends(get_db),
    identity: dict = Depends(require_roles(*ANALYST_ROLES)),
) -> dict:
    result = verify_audit_trail(db)
    result["verified_at"] = datetime.now(UTC).isoformat()
    return result


# ------------------------------------------------------------------- demo lab

def _last_runs(db: Session) -> dict[str, DemoRunRecord]:
    latest: dict[str, DemoRunRecord] = {}
    for run in db.scalars(select(DemoRunRecord).order_by(DemoRunRecord.started_at.desc())).all():
        latest.setdefault(run.scenario_id, run)
    return latest


def _run(row: DemoRunRecord) -> dict[str, Any]:
    return {"run_id": row.run_id, "scenario_id": row.scenario_id, "started_by": row.started_by,
            "started_at": _iso(row.started_at), **row.result_json}


@router.get("/demo/scenarios")
def list_scenarios(db: Session = Depends(get_db),
                   identity: dict = Depends(require_roles(*READ_ROLES))) -> dict:
    latest = _last_runs(db)
    return {"data_provenance": "Synthetic generated data", "items": [
        {**scenario.describe(),
         "last_run": _run(latest[scenario.scenario_id]) if scenario.scenario_id in latest else None}
        for scenario in scenarios.SCENARIOS.values()]}


@router.get("/demo/runs")
def list_runs(limit: int = Query(default=50, ge=1, le=200), db: Session = Depends(get_db),
              identity: dict = Depends(require_roles(*READ_ROLES))) -> dict:
    rows = db.scalars(select(DemoRunRecord).order_by(DemoRunRecord.started_at.desc()).limit(limit)).all()
    return {"total": len(rows), "items": [_run(row) for row in rows]}


@router.post("/demo/scenarios/{scenario_id}/run", status_code=201)
def run_scenario(
    scenario_id: str,
    db: Session = Depends(get_db),
    identity: dict = Depends(require_roles(*ANALYST_ROLES)),
) -> dict:
    if scenario_id not in scenarios.SCENARIOS:
        raise HTTPException(status_code=404, detail="Scenario not found.")
    from app.main import process_and_store          # the normal ingestion path (avoids a circular import)

    started_at = datetime.now(UTC)
    run_id = f"{scenario_id}-{started_at:%Y%m%d%H%M%S}-{secrets.token_hex(2)}"
    # Scenario time starts 25 minutes ago, so every generated event lies in the past.
    start = (started_at - timedelta(minutes=25)).replace(second=0, microsecond=0)
    baseline, events = scenarios.build(scenario_id, run_id, start)

    for raw_event in baseline + events:
        process_and_store(raw_event, db)

    summary = run_analysis(db, actor=identity["username"], run_id=run_id)
    findings = db.scalars(select(FindingRecord).where(
        FindingRecord.scope == run_id, FindingRecord.is_current.is_(True))
        .order_by(FindingRecord.risk_score.desc())).all()
    rules = [row.rule_id for row in db.scalars(select(DetectionRecord).where(
        DetectionRecord.scope == run_id, DetectionRecord.is_current.is_(True))).all()]
    top = findings[0] if findings else None
    comparison = scenarios.compare(scenario_id, rules, top.finding if top else None,
                                   top.decision if top else None)

    result = {
        "events_ingested": len(events), "baseline_events": len(baseline),
        "detection_count": summary["detection_count"], "finding_count": len(findings),
        "finding": None if top is None else {
            "group_id": top.group_id, "finding": top.finding, "risk_score": top.risk_score,
            "risk_level": top.risk_level, "decision": top.decision},
        "comparison": comparison,
        "ground_truth": scenarios.SCENARIOS[scenario_id].ground_truth,
    }
    row = DemoRunRecord(run_id=run_id, scenario_id=scenario_id, started_by=identity["username"],
                        started_at=started_at, result_json=result)
    db.add(row)
    _audit(db, identity["username"], "demo_scenario_run", "demo_run", run_id, {
        "scenario_id": scenario_id, "events_ingested": len(events), "baseline_events": len(baseline),
        "matches_expected": comparison["matches_expected"]})
    db.commit()
    return _run(row)
