from datetime import UTC, datetime
from uuid import uuid4

from models import ConnectionEvent


def execute_containment(event: ConnectionEvent) -> dict:
    incident_id = f"INC-{uuid4().hex[:8].upper()}"

    return {
        "incident_id": incident_id,
        "contained_at": datetime.now(UTC).isoformat(),
        "event_id": event.event_id,
        "user_id": event.user_id,
        "device_id": event.device_id,
        "device_name": event.device_name,
        "endpoint_status": "CONTAINED",
        "session_revoked": True,
        "sensitive_data_access_blocked": True,
        "data_export_blocked": True,
        "incident_ticket_created": True,
        "evidence_snapshot_created": True,
        "trigger": "infection_signal",
    }