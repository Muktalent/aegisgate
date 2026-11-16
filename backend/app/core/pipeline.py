"""End-to-end analysis: events -> detections -> correlation -> risk -> policy.

The same function is meant to serve normal ingestion and Demo Lab replay, so
demonstrations cannot use a separate hardcoded decision path.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from . import CORE_VERSION
from .allowlist import ALLOWLIST_VERSION, AllowEntry, Suppression, apply_allowlist
from .behaviour import BaselineComparison, bucket_metrics, compare_to_baseline, history_for, typical_outbound_bytes
from .correlation import CORRELATION_VERSION, CorrelationGroup, correlate
from .detection import Detection, DetectionEngine
from .events import CanonicalEvent
from .policy import Policy, PolicyDecision, decide
from .risk import AssetContext, RiskAssessment, RiskModel, assess

# Which behavioural metric is the relevant baseline for each detection category.
# Regular outbound connections have none: what marks them is their timing, and a
# host that browses a lot would make a slow beacon look "within baseline".
BASELINE_METRIC = {
    "port_scan": "port_diversity",
    "destination_scan": "destination_diversity",
    "potential_exfiltration": "outbound_bytes",
}


@dataclass(frozen=True)
class Finding:
    group: CorrelationGroup
    baseline: BaselineComparison | None
    assessment: RiskAssessment
    decision: PolicyDecision

    def to_dict(self) -> dict[str, Any]:
        return {
            "group": self.group.to_dict(),
            "detections": [d.to_dict() for d in self.group.detections],
            "baseline": self.baseline.to_dict() if self.baseline else None,
            "risk_assessment": self.assessment.to_dict(),
            "policy_decision": self.decision.to_dict(),
        }


@dataclass(frozen=True)
class AnalysisResult:
    event_count: int
    detections: tuple[Detection, ...]
    findings: tuple[Finding, ...]
    versions: dict[str, str]
    suppressed: tuple[Suppression, ...] = ()


def analyse(
    events: Iterable[CanonicalEvent],
    assets: dict[str, AssetContext] | None = None,
    history: Iterable[CanonicalEvent] = (),
    *,
    engine: DetectionEngine | None = None,
    risk_model: RiskModel | None = None,
    policy: Policy | None = None,
    bucket_seconds: int = 300,
    correlation_window_seconds: int = 600,
    allowlist: Iterable[AllowEntry] = (),
) -> AnalysisResult:
    """``assets`` maps source_ip to inventory context. ``history`` is earlier
    traffic used only to build behavioural baselines. ``allowlist`` holds
    approved-activity entries; detections they fully cover are suppressed
    and returned separately, never dropped silently."""
    batch = list({event.event_id: event for event in events}.values())
    engine = engine or DetectionEngine()
    policy = policy or Policy()
    assets = assets or {}

    past = bucket_metrics(history, bucket_seconds)
    current = bucket_metrics(batch, bucket_seconds)
    first = min((e.timestamp for e in batch), default=None)
    baseline_bytes = typical_outbound_bytes(past, first) if first else {}

    entries = list(allowlist)
    detections, suppressed = apply_allowlist(engine.run(batch, baseline_bytes), batch, entries)
    findings = []
    for group in correlate(detections, correlation_window_seconds):
        baseline = None
        metric = next((BASELINE_METRIC[c] for c in group.categories if c in BASELINE_METRIC), None)
        if metric:
            observed = [getattr(b, metric) for b in current
                        if b.source_ip == group.source_ip and getattr(b, metric) is not None]
            baseline = compare_to_baseline(
                group.source_ip, metric, max(observed) if observed else None,
                history_for(past, group.source_ip, metric, group.window_start))
        assessment = assess(group, assets.get(group.source_ip), baseline, risk_model)
        findings.append(Finding(group, baseline, assessment, decide(assessment, policy)))

    return AnalysisResult(
        event_count=len(batch), detections=tuple(detections), findings=tuple(findings),
        suppressed=tuple(suppressed),
        versions={"allowlist": ALLOWLIST_VERSION if entries else "none","core": CORE_VERSION, "rules": engine.ruleset_version,
                  "correlation": CORRELATION_VERSION,
                  "risk_model": (findings[0].assessment.model_version if findings else "risk-1.0"),
                  "policy": policy.version})
