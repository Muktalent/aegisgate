import pytest

import core_helpers  # noqa: F401  (adds backend to sys.path)
from app.core import audit_chain
from app.core.response import (ACTIONS, ResponseError, SimulationAdapter, impact_of, initial_state,
                               next_state, simulated_target_state)


def test_low_impact_actions_start_proposed_and_high_impact_wait_for_approval():
    assert initial_state("monitor", "soc_analyst") == "proposed"
    assert initial_state("flag_for_investigation", "security_admin") == "proposed"
    for action in ("simulated_connection_block", "simulated_access_denial", "simulated_host_quarantine"):
        assert impact_of(action) == "high" and initial_state(action, "soc_analyst") == "pending_approval"


@pytest.mark.parametrize("role", ["viewer", "ingestor", "nobody"])
def test_read_only_roles_cannot_request_or_change_actions(role):
    with pytest.raises(ResponseError) as error:
        initial_state("monitor", role)
    assert error.value.code == "forbidden"
    for state, operation in (("proposed", "execute"), ("pending_approval", "approve"),
                             ("executed_in_simulation", "rollback")):
        with pytest.raises(ResponseError) as error:
            next_state(state, operation, role)
        assert error.value.code == "forbidden"


def test_full_high_impact_lifecycle():
    state = initial_state("simulated_host_quarantine", "soc_analyst")
    state = next_state(state, "approve", "security_admin")
    assert state == "approved"
    state = next_state(state, "execute", "soc_analyst")
    assert state == "executed_in_simulation"
    assert next_state(state, "rollback", "soc_analyst") == "rolled_back"


def test_analyst_cannot_approve_or_reject():
    for operation in ("approve", "reject"):
        with pytest.raises(ResponseError) as error:
            next_state("pending_approval", operation, "soc_analyst")
        assert error.value.code == "forbidden"
    assert next_state("pending_approval", "reject", "security_admin") == "rejected"


@pytest.mark.parametrize("state,operation", [
    ("pending_approval", "execute"),          # high impact cannot skip approval
    ("rejected", "execute"), ("rejected", "approve"), ("rolled_back", "rollback"),
    ("rolled_back", "execute"), ("proposed", "rollback"), ("proposed", "approve"),
    ("executed_in_simulation", "execute"), ("approved", "approve"), ("failed", "execute")])
def test_invalid_transitions_are_refused(state, operation):
    with pytest.raises(ResponseError) as error:
        next_state(state, operation, "security_admin")
    assert error.value.code == "invalid_transition"


def test_unknown_action_and_operation():
    with pytest.raises(ResponseError) as error:
        initial_state("real_firewall_block", "security_admin")
    assert error.value.code == "unknown_action"
    with pytest.raises(ResponseError) as error:
        next_state("proposed", "delete", "security_admin")
    assert error.value.code == "unknown_operation"


def test_simulation_adapter_never_reports_a_real_change():
    adapter = SimulationAdapter()
    for action in ACTIONS:
        done, undone = adapter.execute(action), adapter.rollback(action)
        assert done.simulated and undone.simulated and done.adapter == "simulation"
        assert done.real_infrastructure_changed is False and undone.real_infrastructure_changed is False
        assert undone.target_state == "normal"
    assert adapter.execute("simulated_host_quarantine").target_state == "quarantined"
    assert "No real" in adapter.execute("simulated_connection_block").effect


def test_simulated_target_state_takes_the_strongest_active_action():
    assert simulated_target_state([]) == "normal"
    assert simulated_target_state(["monitor"]) == "monitored"
    assert simulated_target_state(["monitor", "simulated_host_quarantine", "simulated_connection_block"]) == "quarantined"


# ---- audit chain ---------------------------------------------------------------

def chain(records):
    previous, rows = audit_chain.GENESIS, []
    for audit_id, record in records:
        digest = audit_chain.entry_hash(previous, record)
        rows.append((audit_id, record, previous, digest))
        previous = digest
    return rows


RECORDS = [(i, {"audit_id": i, "actor": "a", "action": f"act-{i}", "details": {"n": i, "ñ": "é"}})
           for i in range(1, 6)]


def test_valid_chain_verifies_and_is_deterministic():
    rows = chain(RECORDS)
    result = audit_chain.verify_chain(rows)
    assert result["valid"] and result["checked"] == 5 and result["latest_hash"] == rows[-1][3]
    assert chain(RECORDS) == rows
    assert audit_chain.canonical({"b": 1, "a": 2}) == audit_chain.canonical({"a": 2, "b": 1})


def test_empty_chain_is_valid():
    assert audit_chain.verify_chain([]) == {"valid": True, "checked": 0, "first_invalid_audit_id": None,
                                            "reason": None, "latest_hash": None}


def test_modified_entry_is_detected_at_its_position():
    rows = chain(RECORDS)
    rows[2] = (3, {**rows[2][1], "actor": "attacker"}, rows[2][2], rows[2][3])
    result = audit_chain.verify_chain(rows)
    assert not result["valid"] and result["first_invalid_audit_id"] == 3 and "content" in result["reason"]


def test_removed_and_reordered_entries_are_detected():
    rows = chain(RECORDS)
    removed = audit_chain.verify_chain(rows[:2] + rows[3:])
    assert not removed["valid"] and removed["first_invalid_audit_id"] == 4 and "link" in removed["reason"]
    reordered = audit_chain.verify_chain([rows[0], rows[2], rows[1]] + rows[3:])
    assert not reordered["valid"] and reordered["first_invalid_audit_id"] == 3


def test_missing_audit_row_is_detected():
    rows = chain(RECORDS)
    rows[4] = (5, None, rows[4][2], rows[4][3])
    result = audit_chain.verify_chain(rows)
    assert not result["valid"] and result["first_invalid_audit_id"] == 5 and "missing" in result["reason"]
