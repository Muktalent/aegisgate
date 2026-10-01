import sys
from pathlib import Path

sys.path.append(
    str(Path(__file__).resolve().parents[1] / "backend")
)

from access_decision import decide_access
from risk_engine import RiskAssessment


def assessment(score: int) -> RiskAssessment:
    return RiskAssessment(
        score=score,
        reasons=["Test assessment."],
    )


def test_low_risk_is_allowed() -> None:
    decision = decide_access(assessment(29))

    assert decision.action == "allow"
    assert decision.requires_mfa is False
    assert decision.requires_analyst_review is False


def test_medium_risk_is_monitored() -> None:
    decision = decide_access(assessment(30))

    assert decision.action == "allow_with_monitoring"
    assert decision.requires_mfa is False
    assert decision.requires_analyst_review is False


def test_high_risk_requires_step_up() -> None:
    decision = decide_access(assessment(60))

    assert decision.action == "step_up_authentication"
    assert decision.requires_mfa is True
    assert decision.requires_analyst_review is True


def test_critical_risk_is_denied() -> None:
    decision = decide_access(assessment(90))

    assert decision.action == "deny"
    assert decision.requires_mfa is False
    assert decision.requires_analyst_review is True