"""Policy and decision engine (AG-10), separate from risk scoring.

The risk engine assesses the situation; this module decides which outcome
the policy permits. Decisions are recommendations or simulated outcomes:
``step_up_authentication`` does not mean an MFA challenge took place, and
``deny`` is never enforced on real infrastructure in the Academic edition.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .risk import RiskAssessment

DECISIONS = ("allow", "allow_with_monitoring", "manual_review", "step_up_authentication", "deny")


@dataclass(frozen=True)
class Policy:
    version: str = "policy-academic-1.0"
    monitor_from: int = 20
    review_from: int = 40
    step_up_from: int = 60
    deny_from: int = 80
    step_up_min_confidence: float = 0.6
    deny_min_confidence: float = 0.8
    deny_min_categories: int = 2


@dataclass(frozen=True)
class PolicyDecision:
    group_id: str
    decision: str
    recommended_actions: tuple[str, ...]
    requires_human_approval: bool
    conditions: tuple[str, ...]
    explanation: str
    policy_version: str
    risk_model_version: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["recommended_actions"] = list(self.recommended_actions)
        data["conditions"] = list(self.conditions)
        return data


ACTIONS = {
    "allow": (),
    "allow_with_monitoring": ("monitor",),
    "manual_review": ("flag_for_investigation",),
    "step_up_authentication": ("simulated_connection_block", "flag_for_investigation"),
    "deny": ("simulated_host_quarantine", "flag_for_investigation"),
}


def decide(assessment: RiskAssessment, policy: Policy | None = None) -> PolicyDecision:
    policy = policy or Policy()
    score, confidence = assessment.risk_score, assessment.detection_confidence
    conditions: list[str] = [f"risk_score={score}", f"detection_confidence={confidence}",
                             f"asset_identified={assessment.asset_identified}",
                             f"corroborating_categories={assessment.corroborating_categories}"]

    if score < policy.monitor_from:
        decision, why = "allow", f"Risk score is below {policy.monitor_from}."
    elif not assessment.asset_identified:
        decision = "manual_review"
        why = ("The source is not an identified asset, so no automatic restriction is selected; "
               "an analyst must establish what the device is.")
    elif score < policy.review_from:
        decision, why = "allow_with_monitoring", f"Risk score is between {policy.monitor_from} and {policy.review_from - 1}."
    elif score < policy.step_up_from:
        decision, why = "manual_review", f"Risk score is between {policy.review_from} and {policy.step_up_from - 1}."
    elif score < policy.deny_from:
        if confidence >= policy.step_up_min_confidence:
            decision = "step_up_authentication"
            why = (f"Risk score is between {policy.step_up_from} and {policy.deny_from - 1} with confidence "
                   f"of at least {policy.step_up_min_confidence}. No real MFA challenge is issued.")
        else:
            decision = "manual_review"
            why = f"Risk score is high but confidence is below {policy.step_up_min_confidence}."
    else:
        confident = confidence >= policy.deny_min_confidence
        corroborated = assessment.corroborating_categories >= policy.deny_min_categories
        conditions += [f"deny_confidence_condition={confident}", f"deny_corroboration_condition={corroborated}"]
        if confident and corroborated:
            decision = "deny"
            why = (f"Risk score is at least {policy.deny_from}, confidence is at least "
                   f"{policy.deny_min_confidence} and {assessment.corroborating_categories} independent "
                   "indicator types agree. Any containment is simulated.")
        else:
            decision = "manual_review"
            why = (f"Risk score is at least {policy.deny_from}, but a simulated denial also needs confidence "
                   f"of at least {policy.deny_min_confidence} and {policy.deny_min_categories} independent "
                   "indicator types. A score alone never selects containment.")

    return PolicyDecision(
        group_id=assessment.group_id, decision=decision, recommended_actions=ACTIONS[decision],
        requires_human_approval=decision in ("deny", "step_up_authentication"),
        conditions=tuple(conditions), explanation=why,
        policy_version=policy.version, risk_model_version=assessment.model_version)
