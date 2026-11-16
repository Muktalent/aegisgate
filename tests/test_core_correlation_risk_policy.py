import pytest

from core_helpers import beacon, host_sweep, ids_alert, office_traffic, port_scan, upload
from app.core.behaviour import compare_to_baseline
from app.core.correlation import correlate
from app.core.detection import DetectionEngine
from app.core.pipeline import analyse
from app.core.policy import Policy, decide
from app.core.risk import AssetContext, RiskModel, assess

KNOWN = AssetContext("lab-ws-001", True, "medium")
CRITICAL = AssetContext("lab-finance-001", True, "critical")


def groups(events, **kw):
    return correlate(DetectionEngine().run(events), **kw)


def recon(src="10.10.10.25"):
    return port_scan(20, src=src) + host_sweep(12, src=src, start=30) + [ids_alert(40, src=src)]


# ---- correlation -------------------------------------------------------------

def test_related_detections_are_grouped_and_evidence_preserved():
    (g,) = groups(recon())
    assert g.finding == "potential_network_reconnaissance" and g.is_correlated
    assert set(g.categories) == {"port_scan", "destination_scan", "ids_alert"}
    assert len(g.detections) == 3 and "does not establish intent" in g.explanation


def test_unrelated_sources_and_distant_times_stay_separate():
    two_sources = groups(port_scan(20, src="10.10.10.25") + host_sweep(12, src="10.10.10.50"))
    assert sorted(g.finding for g in two_sources) == ["destination_scan", "port_scan"]
    far_apart = groups(port_scan(20) + host_sweep(12, start=3600))
    assert len(far_apart) == 2 and not any(g.is_correlated for g in far_apart)


def test_correlation_is_reproducible_and_duplicate_safe():
    events = recon()
    first, second = groups(events), groups(list(reversed(events)) + events)
    assert [g.group_id for g in first] == [g.group_id for g in second] and len(second) == 1


def test_other_patterns():
    assert groups(beacon(8) + [ids_alert(100, dst="198.51.100.23")])[0].finding == "potential_command_and_control"
    assert groups(upload(60, src="10.10.10.25") + [ids_alert(20)])[0].finding == "potential_data_exfiltration"


def test_invalid_window():
    with pytest.raises(ValueError):
        correlate([], window_seconds=0)


# ---- risk --------------------------------------------------------------------

def score(events, asset=KNOWN, baseline=None):
    (g,) = groups(events)
    return assess(g, asset, baseline)


def above_baseline():
    return compare_to_baseline("10.10.10.25", "port_diversity", 20, [2, 3, 2, 4, 3, 2, 3, 3])


def test_scores_are_differentiated_not_all_maximum():
    cases = [
        score(port_scan(16)),                                   # one weak indicator
        score(port_scan(50, step=0.5)),                         # one strong indicator
        score(recon()),                                         # three indicators, no baseline
        score(recon(), baseline=above_baseline()),              # ... and above baseline
        score(recon(), CRITICAL, above_baseline()),             # ... on a critical asset
    ]
    values = [c.risk_score for c in cases]
    assert values == sorted(values) and len(set(values)) == 5, values
    assert [c.risk_level for c in cases] == ["low", "medium", "medium", "high", "critical"]
    assert all(0 <= v <= 100 for v in values) and values[-1] < 100


def test_factors_explain_the_score():
    a = score(recon(), CRITICAL)
    assert abs(sum(f.contribution for f in a.factors) - a.risk_score) <= 1
    names = [f.factor for f in a.factors]
    assert names[0].startswith("evidence_") and "asset_criticality" in names
    assert sum(n.startswith("corroboration_") for n in names) == 2
    assert a.corroborating_categories == 3 and a.max_severity == "high"


def test_severity_confidence_and_criticality_are_reported_separately():
    a = score(port_scan(20), CRITICAL)
    assert a.max_severity == "medium" and 0 < a.detection_confidence < 1
    assert a.asset_criticality == "critical" and a.risk_score != 100


def test_unknown_asset_is_flagged_not_fabricated():
    a = score(port_scan(20), None)
    assert not a.asset_identified and a.asset_criticality is None
    assert {"asset_identity", "asset_criticality"} <= set(a.missing_context)
    assert any(f.factor == "unidentified_asset" for f in a.factors)


def test_missing_baseline_is_reported_and_adds_nothing():
    a = score(port_scan(20))
    assert "behavioural_baseline" in a.missing_context
    assert not any("baseline" in f.factor for f in a.factors)


def test_conflicting_and_supporting_baseline_evidence():
    history = [18, 22, 20, 19, 21, 20, 23, 19]            # this host normally touches ~20 ports
    within = compare_to_baseline("10.10.10.25", "port_diversity", 20, history)
    above = compare_to_baseline("10.10.10.25", "port_diversity", 20, [2, 3, 2, 4, 3, 2, 3, 3])
    plain, lower, higher = score(port_scan(20)), score(port_scan(20), baseline=within), \
        score(port_scan(20), baseline=above)
    assert lower.risk_score == plain.risk_score - 10 and higher.risk_score == plain.risk_score + 10
    assert any("Conflicting evidence" in f.detail for f in lower.factors)


def test_low_criticality_reduces_and_score_is_bounded():
    assert score(recon(), AssetContext("a", True, "low")).risk_score < score(recon()).risk_score
    huge = RiskModel(severity_points={"low": 500, "medium": 500, "high": 500, "critical": 500})
    (g,) = groups(recon())
    assert assess(g, CRITICAL, model=huge).risk_score == 100


def test_same_input_same_assessment():
    events = recon()
    assert score(events) == score(list(reversed(events)))


# ---- policy ------------------------------------------------------------------

def decision(events, asset=KNOWN, policy=None):
    return decide(score(events, asset), policy)


def test_decisions_follow_risk_bands():
    assert decision(port_scan(16)).decision == "allow_with_monitoring"
    assert decision(port_scan(50, step=0.5)).decision == "manual_review"
    assert decision(recon()).decision == "manual_review"
    (g,) = groups(recon())
    step_up = decide(assess(g, KNOWN, above_baseline()))
    assert step_up.decision == "step_up_authentication" and step_up.requires_human_approval
    assert "No real MFA challenge" in step_up.explanation
    deny = decide(assess(g, CRITICAL, above_baseline()))
    assert deny.decision == "deny" and "simulated_host_quarantine" in deny.recommended_actions
    assert "simulated" in deny.explanation


def test_score_alone_never_selects_denial():
    strict = RiskModel(severity_points={"low": 20, "medium": 40, "high": 100, "critical": 100})
    (g,) = groups(port_scan(50, step=0.5))               # one indicator type only
    a = assess(g, CRITICAL, model=strict)
    assert a.risk_score >= 80 and a.corroborating_categories == 1
    d = decide(a)
    assert d.decision == "manual_review" and "score alone never selects containment" in d.explanation


def test_unknown_asset_goes_to_manual_review_even_at_high_risk():
    (g,) = groups(recon())
    a = assess(g, AssetContext(None, False, None), above_baseline())
    d = decide(a)
    assert a.risk_score >= 60
    assert d.decision == "manual_review" and "not an identified asset" in d.explanation


def test_low_score_is_allowed_and_decision_records_versions():
    quiet = RiskModel(severity_points={"low": 5, "medium": 5, "high": 5, "critical": 5})
    (g,) = groups(port_scan(16))
    d = decide(assess(g, KNOWN, model=quiet))
    assert d.decision == "allow" and d.recommended_actions == ()
    assert d.policy_version == "policy-academic-1.0" and d.risk_model_version == "risk-1.0"


def test_policy_thresholds_are_configurable():
    assert decision(port_scan(16), policy=Policy(version="p2", review_from=20)).decision == "manual_review"


# ---- pipeline ----------------------------------------------------------------

def test_pipeline_normal_traffic_has_no_findings():
    result = analyse(office_traffic(), {"10.10.10.25": KNOWN})
    assert result.detections == () and result.findings == () and result.event_count > 50


def test_pipeline_port_scan_with_history_uses_real_baseline():
    result = analyse(port_scan(20), {"10.10.10.25": KNOWN}, history=office_traffic())
    (finding,) = result.findings
    assert finding.baseline.status == "above_baseline" and finding.baseline.metric == "port_diversity"
    assert any(f.factor == "above_behavioural_baseline" for f in finding.assessment.factors)
    assert finding.decision.decision in ("allow_with_monitoring", "manual_review")
    assert set(result.versions) == {"allowlist", "core", "rules", "correlation", "risk_model", "policy"}


def test_pipeline_cold_start_states_insufficient_baseline():
    (finding,) = analyse(port_scan(20), {"10.10.10.25": KNOWN}).findings
    assert finding.baseline.status == "insufficient_baseline_data"
    assert "behavioural_baseline" in finding.assessment.missing_context


def test_pipeline_unknown_device_and_serialisation():
    (finding,) = analyse(recon(src="10.10.10.99")).findings
    assert finding.decision.decision == "manual_review"
    data = finding.to_dict()
    assert data["risk_assessment"]["risk_score"] == finding.assessment.risk_score
    assert len(data["detections"]) == 3 and data["policy_decision"]["policy_version"]


def test_pipeline_mixed_sources_are_scored_independently():
    events = recon("10.10.10.50") + port_scan(16, src="10.10.10.25") + office_traffic(src="10.10.10.30")
    result = analyse(events, {"10.10.10.50": CRITICAL, "10.10.10.25": KNOWN})
    by_source = {f.group.source_ip: f for f in result.findings}
    assert set(by_source) == {"10.10.10.50", "10.10.10.25"}
    assert by_source["10.10.10.50"].assessment.risk_score > by_source["10.10.10.25"].assessment.risk_score
