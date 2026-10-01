import json
from pathlib import Path

from audit_logger import write_audit_record, write_containment_record
from containment import execute_containment
from models import ConnectionEvent
from policy_engine import decide_access
from risk_engine import calculate_risk


project_root = Path(__file__).resolve().parent.parent
events_file = project_root / "data" / "connection_events.json"

with events_file.open("r", encoding="utf-8") as file:
    raw_events = json.load(file)

events = [ConnectionEvent.model_validate(event) for event in raw_events]

print(f"Validated {len(events)} connection events.\n")

for event in events:
    assessment = calculate_risk(event)
    access_decision = decide_access(event, assessment)
    audit_record = write_audit_record(event, assessment, access_decision)

    print(f"Audit ID: {audit_record['audit_id']}")
    print(f"Event: {event.event_id}")
    print(f"User: {event.user_id}")
    print(f"Device: {event.device_name}")
    print(f"Risk score: {assessment.score}/100")
    print(f"Decision: {access_decision.decision}")
    print(
        "Allowed resources: "
        + (
            ", ".join(access_decision.allowed_resources)
            if access_decision.allowed_resources
            else "None"
        )
    )
    print(f"Manual review required: {access_decision.requires_manual_review}")
    print(f"Policy reason: {access_decision.reason}")
    print("Risk reasons:")

    if assessment.reasons:
        for reason in assessment.reasons:
            print(f"- {reason}")
    else:
        print("- No elevated-risk signals detected.")

    if access_decision.decision == "CONTAINMENT":
        containment_record = execute_containment(event)
        containment_audit = write_containment_record(containment_record)

        print("\nContainment actions:")
        print(f"- Incident ID: {containment_record['incident_id']}")
        print(f"- Endpoint status: {containment_record['endpoint_status']}")
        print(f"- Session revoked: {containment_record['session_revoked']}")
        print(
            "- Sensitive data access blocked: "
            f"{containment_record['sensitive_data_access_blocked']}"
        )
        print(f"- Data export blocked: {containment_record['data_export_blocked']}")
        print(
            "- Evidence snapshot created: "
            f"{containment_record['evidence_snapshot_created']}"
        )

    print()