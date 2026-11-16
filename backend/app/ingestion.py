"""Ingestion: normalise raw telemetry and correlate it with the asset inventory.

Ingestion deliberately makes no security decision. Risk and policy are decided
by the analysis core (``app.core.pipeline``) over correlated, windowed
findings, never per single event. The earlier per-event risk engine was
removed; it is preserved in git under the tag ``prototype-v1``.
"""

from typing import Any

from telemetry_adapters import normalize_network_telemetry
from telemetry_context import connection_event_from_telemetry

PENDING_ANALYSIS = "pending_analysis"
MANUAL_REVIEW = "manual_review"

_ANALYSIS_NOTE = (
    "Stored as evidence. Risk and policy are decided by the analysis core "
    "over correlated findings (POST /api/v1/analysis/run), not per event."
)


def normalise_event(raw_event: dict[str, Any]) -> dict[str, Any]:
    """Return the stored representation of one raw Suricata/Zeek event.

    Raises ``ValueError`` for telemetry that cannot be normalised."""
    telemetry = normalize_network_telemetry(raw_event)
    telemetry_json = telemetry.model_dump(mode="json", exclude={"raw_event"})

    try:
        connection_event = connection_event_from_telemetry(telemetry)
    except ValueError as error:
        return {
            "status": "unresolved_asset",
            "telemetry": telemetry_json,
            "connection_event": None,
            "risk_assessment": None,
            "access_decision": {
                "action": MANUAL_REVIEW,
                "requires_mfa": False,
                "requires_analyst_review": True,
                "reasons": [
                    "The source IP could not be correlated with a known asset.",
                    _ANALYSIS_NOTE,
                ],
            },
            "error": str(error),
        }

    return {
        "status": "processed",
        "telemetry": telemetry_json,
        "connection_event": connection_event.model_dump(mode="json"),
        "risk_assessment": None,
        "access_decision": {
            "action": PENDING_ANALYSIS,
            "requires_mfa": False,
            "requires_analyst_review": False,
            "reasons": [_ANALYSIS_NOTE],
        },
        "error": None,
    }
