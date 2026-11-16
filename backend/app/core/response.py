"""Simulated response engine (AG-11): action catalogue and state machine.

Nothing in this module can touch real infrastructure. The only adapter is the
simulation adapter, which records the effect an action would have.
"""
from __future__ import annotations

from dataclasses import dataclass

LOW_IMPACT = "low"
HIGH_IMPACT = "high"

# action -> (impact, simulated effect, resulting simulated state of the target)
ACTIONS: dict[str, tuple[str, str, str]] = {
    "monitor": (LOW_IMPACT, "The source is added to the simulated watch list.", "monitored"),
    "flag_for_investigation": (LOW_IMPACT, "The finding is flagged for analyst investigation.", "flagged"),
    "simulated_connection_block": (
        HIGH_IMPACT, "Connections from the source would be blocked. No real firewall rule is created.",
        "connection_blocked"),
    "simulated_access_denial": (
        HIGH_IMPACT, "Access for the source would be denied. No real session or account is changed.",
        "access_denied"),
    "simulated_host_quarantine": (
        HIGH_IMPACT, "The host would be isolated from the network. No real isolation is applied.",
        "quarantined"),
}

STATES = ("proposed", "pending_approval", "approved", "rejected",
          "executed_in_simulation", "rolled_back", "failed")
ACTIVE_STATES = ("proposed", "pending_approval", "approved", "executed_in_simulation")
STATE_RANK = ("normal", "flagged", "monitored", "connection_blocked", "access_denied", "quarantined")

ANALYST_ROLES = ("soc_analyst", "security_admin")
APPROVER_ROLES = ("security_admin",)

# (state, operation) -> (next state, roles allowed)
TRANSITIONS: dict[tuple[str, str], tuple[str, tuple[str, ...]]] = {
    ("pending_approval", "approve"): ("approved", APPROVER_ROLES),
    ("pending_approval", "reject"): ("rejected", APPROVER_ROLES),
    ("proposed", "execute"): ("executed_in_simulation", ANALYST_ROLES),
    ("approved", "execute"): ("executed_in_simulation", ANALYST_ROLES),
    ("executed_in_simulation", "rollback"): ("rolled_back", ANALYST_ROLES),
}
OPERATIONS = ("approve", "reject", "execute", "rollback")


class ResponseError(Exception):
    """``code`` is one of: unknown_action, unknown_operation, forbidden, invalid_transition."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def impact_of(action_type: str) -> str:
    if action_type not in ACTIONS:
        raise ResponseError("unknown_action", f"Unsupported response action: {action_type}.")
    return ACTIONS[action_type][0]


def initial_state(action_type: str, role: str) -> str:
    """High-impact actions wait for approval; low-impact ones can be executed directly."""
    impact = impact_of(action_type)
    if role not in ANALYST_ROLES:
        raise ResponseError("forbidden", "Your role cannot request response actions.")
    return "pending_approval" if impact == HIGH_IMPACT else "proposed"


def next_state(state: str, operation: str, role: str) -> str:
    if operation not in OPERATIONS:
        raise ResponseError("unknown_operation", f"Unsupported operation: {operation}.")
    rule = TRANSITIONS.get((state, operation))
    if rule is None:
        raise ResponseError("invalid_transition",
                            f"An action in state '{state}' cannot be changed with '{operation}'.")
    target, roles = rule
    if role not in roles:
        raise ResponseError("forbidden", f"Your role cannot {operation} this action.")
    return target


@dataclass(frozen=True)
class SimulationOutcome:
    simulated: bool
    adapter: str
    effect: str
    target_state: str
    real_infrastructure_changed: bool = False


class SimulationAdapter:
    """The only adapter available in the Academic edition."""
    name = "simulation"

    def execute(self, action_type: str) -> SimulationOutcome:
        impact_of(action_type)
        _, effect, state = ACTIONS[action_type]
        return SimulationOutcome(True, self.name, effect, state)

    def rollback(self, action_type: str) -> SimulationOutcome:
        impact_of(action_type)
        return SimulationOutcome(True, self.name, "The simulated effect was removed.", "normal")


def simulated_target_state(executed_action_types: list[str]) -> str:
    """Strongest simulated state among the actions currently in effect."""
    states = [ACTIONS[a][2] for a in executed_action_types if a in ACTIONS]
    return max(states, key=STATE_RANK.index, default="normal")
