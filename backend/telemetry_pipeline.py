from typing import Any

from access_decision import decide_access
from risk_engine import RiskAssessment, calculate_risk
from telemetry_adapters import normalize_network_telemetry
from telemetry_context import connection_event_from_telemetry
from telemetry_models import NetworkTelemetryEvent


def process_network_event(
    raw_event: dict[str, Any],
) -> dict[str, Any]:
    telemetry: NetworkTelemetryEvent = normalize_network_telemetry(
        raw_event
    )

    try:
        connection_event = connection_event_from_telemetry(
            telemetry
        )
    except ValueError as error:
        return {
            "status": "unresolved_asset",
            "telemetry": telemetry.model_dump(
                mode="json",
                exclude={"raw_event"},
            ),
            "error": str(error),
            "access_decision": {
                "action": "manual_review",
                "requires_mfa": False,
                "requires_analyst_review": True,
                "reasons": [
                    "The source IP could not be correlated "
                    "with a known asset."
                ],
            },
        }

    assessment: RiskAssessment = calculate_risk(connection_event)

    decision = decide_access(assessment)

    return {
        "status": "processed",
        "telemetry": telemetry.model_dump(
            mode="json",
            exclude={"raw_event"},
        ),
        "connection_event": connection_event.model_dump(
            mode="json",
        ),
        "risk_assessment": {
            "score": assessment.score,
            "reasons": assessment.reasons,
        },
        "access_decision": {
            "action": decision.action,
            "requires_mfa": decision.requires_mfa,
            "requires_analyst_review": (
                decision.requires_analyst_review
            ),
            "reasons": decision.reasons,
        },
    }