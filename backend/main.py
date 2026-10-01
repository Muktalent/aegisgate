import json
import os
from pathlib import Path
from uuid import uuid4



from fastapi import Depends, FastAPI, HTTPException, Query, status
from pydantic import BaseModel

from audit_logger import write_audit_record, write_containment_record
from containment import execute_containment
from models import ConnectionEvent
from policy_engine import decide_access
from risk_engine import calculate_risk
from security import (
    authenticate_lab_user,
    create_access_token,
    require_roles,
)


project_root = Path(__file__).resolve().parent.parent
default_audit_file = project_root / "reports" / "audit_log.jsonl"
audit_file = Path(
    os.getenv("AEGIS_AUDIT_FILE", str(default_audit_file))
)


app = FastAPI(
    title="AegisGate API",
    version="0.2.0-lab",
    description="Zero-Trust access-decision service with explainable risk scoring.",
)


class TokenRequest(BaseModel):
    username: str
    password: str


def read_audit_records() -> list[dict]:
    if not audit_file.exists():
        return []

    records = []

    with audit_file.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                records.append(
                    {
                        "record_type": "invalid_audit_record",
                        "line_number": line_number,
                        "raw_value": line,
                    }
                )

    return records


@app.get("/")
def health_check():
    return {
        "service": "AegisGate",
        "status": "healthy",
        "version": "0.2.0-lab",
    }


@app.post("/auth/token")
def issue_access_token(credentials: TokenRequest):
    identity = authenticate_lab_user(
        username=credentials.username,
        password=credentials.password,
    )

    if identity is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid laboratory credentials.",
        )

    token = create_access_token(
        username=identity["username"],
        role=identity["role"],
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in_minutes": 30,
        "role": identity["role"],
    }


@app.post("/events/access")
def evaluate_access(
    event: ConnectionEvent,
    identity: dict = Depends(require_roles("ingestor", "security_admin")),
):
    correlation_id = str(uuid4())
    assessment = calculate_risk(event)
    decision = decide_access(event, assessment)

    audit_record = write_audit_record(
        event=event,
        assessment=assessment,
        decision=decision,
        actor_username=identity["username"],
        actor_role=identity["role"],
        correlation_id=correlation_id,
    )

    containment_record = None

    if decision.decision == "CONTAINMENT":
        containment_action = execute_containment(event)
        containment_record = write_containment_record(
            containment_record=containment_action,
            actor_username=identity["username"],
            actor_role=identity["role"],
            correlation_id=correlation_id,
        )

    response = {
        "event_id": event.event_id,
        "risk_score": assessment.score,
        "risk_reasons": assessment.reasons,
        "decision": decision.decision,
        "allowed_resources": decision.allowed_resources,
        "requires_manual_review": decision.requires_manual_review,
        "policy_reason": decision.reason,
        "audit_recorded": True,
        "audit_id": audit_record["audit_id"],
        "correlation_id": correlation_id,
        "processed_by": identity["username"],
    }

    if containment_record is not None:
        response["incident_id"] = containment_record["incident_id"]
        response["containment_recorded"] = True
        response["endpoint_status"] = containment_record["endpoint_status"]

    return response


@app.get("/audit/events")
def list_audit_events(
    limit: int = Query(default=50, ge=1, le=200),
    decision: str | None = None,
    identity: dict = Depends(require_roles("soc_analyst", "security_admin")),
):
    records = read_audit_records()

    decision_records = [
        record
        for record in records
        if "decision" in record
        and (decision is None or record["decision"] == decision.upper())
    ]

    return {
        "count": len(decision_records[-limit:]),
        "filters": {
            "decision": decision.upper() if decision else None,
            "limit": limit,
        },
        "events": decision_records[-limit:],
        "queried_by": identity["username"],
    }


@app.get("/audit/events/{event_id}")
def get_audit_event(
    event_id: str,
    identity: dict = Depends(require_roles("soc_analyst", "security_admin")),
):
    records = read_audit_records()

    matching_records = [
        record
        for record in records
        if record.get("event_id") == event_id and "decision" in record
    ]

    if not matching_records:
        raise HTTPException(
            status_code=404,
            detail=f"No access-decision audit record found for event_id '{event_id}'.",
        )

    return {
        "event_id": event_id,
        "count": len(matching_records),
        "events": matching_records,
        "queried_by": identity["username"],
    }


@app.get("/incidents")
def list_incidents(
    limit: int = Query(default=50, ge=1, le=200),
    identity: dict = Depends(require_roles("soc_analyst", "security_admin")),
):
    records = read_audit_records()

    incidents = [
        record
        for record in records
        if record.get("record_type") == "containment_action"
    ]

    return {
        "count": len(incidents[-limit:]),
        "limit": limit,
        "incidents": incidents[-limit:],
        "queried_by": identity["username"],
    }


@app.get("/incidents/{incident_id}")
def get_incident(
    incident_id: str,
    identity: dict = Depends(require_roles("soc_analyst", "security_admin")),
):
    records = read_audit_records()

    incident = next(
        (
            record
            for record in records
            if record.get("record_type") == "containment_action"
            and record.get("incident_id") == incident_id
        ),
        None,
    )

    if incident is None:
        raise HTTPException(
            status_code=404,
            detail=f"No containment incident found for incident_id '{incident_id}'.",
        )

    return {
        **incident,
        "queried_by": identity["username"],
    }