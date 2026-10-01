from dataclasses import dataclass

from models import ConnectionEvent, ResourceSensitivity
from risk_engine import RiskAssessment


@dataclass
class AccessDecision:
    decision: str
    allowed_resources: list[str]
    requires_manual_review: bool
    reason: str


def decide_access(
    event: ConnectionEvent,
    assessment: RiskAssessment,
) -> AccessDecision:
    if event.infection_signal:
        return AccessDecision(
            decision="CONTAINMENT",
            allowed_resources=[],
            requires_manual_review=True,
            reason="Possible infection signal requires immediate containment.",
        )

    if (
        not event.mfa_success
        and event.resource_sensitivity
        in {ResourceSensitivity.HIGH, ResourceSensitivity.CRITICAL}
    ):
        return AccessDecision(
            decision="BLOCK",
            allowed_resources=[],
            requires_manual_review=True,
            reason="MFA failure combined with a sensitive resource request.",
        )

    if assessment.score >= 75:
        return AccessDecision(
            decision="QUARANTINE",
            allowed_resources=["quarantine_portal"],
            requires_manual_review=True,
            reason="High contextual risk requires restricted quarantine access.",
        )

    if assessment.score >= 50:
        return AccessDecision(
            decision="REVIEW_REQUIRED",
            allowed_resources=["review_portal", "device_registration"],
            requires_manual_review=True,
            reason="Access requires administrator verification before approval.",
        )

    if assessment.score >= 25:
        return AccessDecision(
            decision="LIMITED_ACCESS",
            allowed_resources=["self_service_portal", "device_registration"],
            requires_manual_review=False,
            reason="Only low-risk resources are available until device trust improves.",
        )

    return AccessDecision(
        decision="ALLOW",
        allowed_resources=["crm", "knowledge_base", "internal_apps"],
        requires_manual_review=False,
        reason="Connection meets the current baseline security requirements.",
    )