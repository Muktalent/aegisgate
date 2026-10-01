import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from models import ConnectionEvent
from policy_engine import AccessDecision
from risk_engine import RiskAssessment


project_root = Path(__file__).resolve().parent.parent
audit_file = project_root / "reports" / "audit_log.jsonl"

VALID_REVIEW_OUTCOMES = {
    "APPROVE_LIMITED_ACCESS",
    "KEEP_QUARANTINED",
    "BLOCK_CONNECTION",
}


def submit_manual_review(
    event: ConnectionEvent,
    assessment: RiskAssessment,
    initial_decision: AccessDecision,
    reviewer: str,
    outcome: str,
    notes: str,
) -> dict:
    if outcome not in VALID_REVIEW_OUTCOMES:
        raise ValueError(
            f"Invalid review outcome. Choose one of: {sorted(VALID_REVIEW_OUTCOMES)}"
        )

    allowed_resources = []

    if outcome == "APPROVE_LIMITED_ACCESS":
        allowed_resources = ["self_service_portal", "device_registration"]

    review_record = {
        "audit_id": str(uuid4()),
        "created_at": datetime.now(UTC).isoformat(),
        "record_type": "manual_review",
        "event_id": event.event_id,
        "reviewer": reviewer,
        "initial_decision": initial_decision.decision,
        "risk_score": assessment.score,
        "outcome": outcome,
        "allowed_resources_after_review": allowed_resources,
        "notes": notes,
    }

    with audit_file.open("a", encoding="utf-8") as file:
        file.write(json.dumps(review_record) + "\n")

    return review_record