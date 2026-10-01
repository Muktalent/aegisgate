from dataclasses import dataclass

from risk_engine import RiskAssessment


@dataclass
class AccessDecision:
    action: str
    requires_mfa: bool
    requires_analyst_review: bool
    reasons: list[str]


def decide_access(
    assessment: RiskAssessment,
) -> AccessDecision:
    if assessment.score >= 90:
        return AccessDecision(
            action="deny",
            requires_mfa=False,
            requires_analyst_review=True,
            reasons=assessment.reasons,
        )

    if assessment.score >= 60:
        return AccessDecision(
            action="step_up_authentication",
            requires_mfa=True,
            requires_analyst_review=True,
            reasons=assessment.reasons,
        )

    if assessment.score >= 30:
        return AccessDecision(
            action="allow_with_monitoring",
            requires_mfa=False,
            requires_analyst_review=False,
            reasons=assessment.reasons,
        )

    return AccessDecision(
        action="allow",
        requires_mfa=False,
        requires_analyst_review=False,
        reasons=assessment.reasons,
    )