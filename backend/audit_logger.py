import json
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4
from audit_integrity import sign_audit_record
from models import ConnectionEvent
from policy_engine import AccessDecision
from risk_engine import RiskAssessment


project_root = Path(__file__).resolve().parent.parent
default_audit_file = project_root / "reports" / "audit_log.jsonl"
audit_file = Path(
    os.getenv("AEGIS_AUDIT_FILE", str(default_audit_file))
)




def write_audit_record(
    event: ConnectionEvent,
    assessment: RiskAssessment,
    decision: AccessDecision,
    actor_username: str,
    actor_role: str,
    correlation_id: str,
) -> dict:
    audit_record = {
        "audit_id": str(uuid4()),
        "created_at": datetime.now(UTC).isoformat(),
        "record_type": "access_decision",
        "correlation_id": correlation_id,
        "actor_username": actor_username,
        "actor_role": actor_role,
        "event_id": event.event_id,
        "user_id": event.user_id,
        "device_id": event.device_id,
        "device_name": event.device_name,
        "resource": event.resource,
        "requested_action": event.requested_action.value,
        "risk_score": assessment.score,
        "risk_reasons": assessment.reasons,
        "decision": decision.decision,
        "allowed_resources": decision.allowed_resources,
        "requires_manual_review": decision.requires_manual_review,
        "policy_reason": decision.reason,
    }
    audit_record = sign_audit_record(audit_record, audit_file)
    with audit_file.open("a", encoding="utf-8") as file:
        file.write(json.dumps(audit_record) + "\n")

    return audit_record


def write_containment_record(
    containment_record: dict,
    actor_username: str,
    actor_role: str,
    correlation_id: str,
) -> dict:
    audit_record = {
        "audit_id": str(uuid4()),
        "created_at": datetime.now(UTC).isoformat(),
        "record_type": "containment_action",
        "correlation_id": correlation_id,
        "actor_username": actor_username,
        "actor_role": actor_role,
        **containment_record,
    }
    audit_record = sign_audit_record(audit_record, audit_file)
    with audit_file.open("a", encoding="utf-8") as file:
        file.write(json.dumps(audit_record) + "\n")

    return audit_record