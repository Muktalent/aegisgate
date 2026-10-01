import json
from pathlib import Path

from manual_review import submit_manual_review
from models import ConnectionEvent
from policy_engine import decide_access
from risk_engine import calculate_risk


project_root = Path(__file__).resolve().parent.parent
events_file = project_root / "data" / "connection_events.json"

with events_file.open("r", encoding="utf-8") as file:
    raw_events = json.load(file)

events = [ConnectionEvent.model_validate(event) for event in raw_events]

event_to_review = next(event for event in events if event.event_id == "evt-002")

assessment = calculate_risk(event_to_review)
initial_decision = decide_access(event_to_review, assessment)

print("Manual review simulation")
print(f"Event: {event_to_review.event_id}")
print(f"Initial decision: {initial_decision.decision}")
print(f"Risk score: {assessment.score}/100")
print()

review_record = submit_manual_review(
    event=event_to_review,
    assessment=assessment,
    initial_decision=initial_decision,
    reviewer="security.analyst@aegis-demo.local",
    outcome="KEEP_QUARANTINED",
    notes=(
        "Device is unmanaged and requests financial-data export from an unusual "
        "location outside normal working hours. Maintain quarantine pending "
        "device ownership and security-posture verification."
    ),
)

print("Review recorded successfully.")
print(f"Review audit ID: {review_record['audit_id']}")
print(f"Outcome: {review_record['outcome']}")
print(
    "Allowed resources after review: "
    + (
        ", ".join(review_record["allowed_resources_after_review"])
        if review_record["allowed_resources_after_review"]
        else "None"
    )
)