from datetime import datetime
from uuid import uuid4

from asset_correlation import find_asset_by_ip
from models import (
    ConnectionEvent,
    EndpointHealth,
    RequestedAction,
    ResourceSensitivity,
)
from telemetry_models import NetworkTelemetryEvent


def endpoint_health_from_telemetry(
    event: NetworkTelemetryEvent,
    asset_health: str,
) -> EndpointHealth:
    current_health = EndpointHealth(asset_health.lower())

    if event.is_malicious and event.severity <= 2:
        return EndpointHealth.SUSPICIOUS

    return current_health


def connection_event_from_telemetry(
    event: NetworkTelemetryEvent,
) -> ConnectionEvent:
    asset = find_asset_by_ip(event.source_ip)

    if asset is None:
        raise ValueError(
            f"No asset inventory record found for {event.source_ip}."
        )

    return ConnectionEvent(
        event_id=f"{event.source}-{uuid4()}",
        timestamp=event.timestamp,
        user_id=asset["user_id"],
        device_id=asset["device_id"],
        device_name=asset["device_name"],
        managed_device=asset["managed_device"],
        device_compliant=asset["device_compliant"],
        mfa_success=True,
        location=asset["location"],
        known_location=asset["known_location"],
        usual_hours=asset["usual_hours"],
        resource=asset["resource"],
        resource_sensitivity=ResourceSensitivity(
            asset["resource_sensitivity"].lower()
        ),
        requested_action=RequestedAction(
            asset["requested_action"].lower()
        ),
        failed_logins_24h=asset["failed_logins_24h"],
        endpoint_health=endpoint_health_from_telemetry(
            event,
            asset["endpoint_health"],
        ),
        infection_signal=event.is_malicious,
    )