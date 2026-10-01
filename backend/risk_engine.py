from dataclasses import dataclass

from models import ConnectionEvent, EndpointHealth, RequestedAction, ResourceSensitivity


@dataclass
class RiskAssessment:
    score: int
    reasons: list[str]


def calculate_risk(event: ConnectionEvent) -> RiskAssessment:
    score = 0
    reasons = []

    if not event.managed_device:
        score += 25
        reasons.append("Device is not managed by the organisation.")

    if not event.device_compliant:
        score += 20
        reasons.append("Device does not meet the required security posture.")

    if not event.mfa_success:
        score += 30
        reasons.append("Multi-factor authentication was not successfully completed.")

    if not event.known_location:
        score += 15
        reasons.append("Connection originates from a new or unusual location.")

    if not event.usual_hours:
        score += 10
        reasons.append("Connection occurred outside the user's normal hours.")

    sensitivity_scores = {
        ResourceSensitivity.LOW: 0,
        ResourceSensitivity.MEDIUM: 5,
        ResourceSensitivity.HIGH: 15,
        ResourceSensitivity.CRITICAL: 25,
    }

    score += sensitivity_scores[event.resource_sensitivity]

    if event.resource_sensitivity in {
        ResourceSensitivity.HIGH,
        ResourceSensitivity.CRITICAL,
    }:
        reasons.append(
            f"Requested resource has {event.resource_sensitivity.value} sensitivity."
        )

    action_scores = {
        RequestedAction.VIEW_CUSTOMER_RECORDS: 0,
        RequestedAction.EXPORT_DATA: 20,
        RequestedAction.DELETE_RECORDS: 30,
        RequestedAction.CHANGE_BANK_DETAILS: 30,
    }

    score += action_scores[event.requested_action]

    if event.requested_action in {
        RequestedAction.EXPORT_DATA,
        RequestedAction.DELETE_RECORDS,
        RequestedAction.CHANGE_BANK_DETAILS,
    }:
        reasons.append(
            f"Requested action '{event.requested_action.value}' has a high business impact."
        )

    if event.failed_logins_24h >= 5:
        score += 25
        reasons.append(
            "Multiple failed login attempts were detected in the last 24 hours."
        )

    if event.endpoint_health == EndpointHealth.UNKNOWN:
        score += 10
        reasons.append("Endpoint security health is unknown.")

    if event.endpoint_health == EndpointHealth.SUSPICIOUS:
        score += 30
        reasons.append("Endpoint security health is suspicious.")

    if event.endpoint_health == EndpointHealth.INFECTED:
        score += 60
        reasons.append("Endpoint is marked as infected.")

    if event.infection_signal:
        score += 60
        reasons.append("A possible infection or malicious activity signal was received.")

    return RiskAssessment(
        score=min(score, 100),
        reasons=reasons,
    )