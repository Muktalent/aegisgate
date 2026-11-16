"""Explainable risk engine (AG-09).

Keeps five concepts apart: detection severity, detection confidence, asset
criticality, the risk score, and (in policy.py) the policy decision.

Score, bounded to 0..100:

    evidence      = severity_points(strongest detection) * its confidence
    corroboration = sum(15 * confidence) over each further independent category, max 30
                    (a category sharing more than half its events with one already
                    counted is not independent and adds nothing)
    baseline      = +10 above baseline, -10 within baseline, 0 if unknown
    subtotal      = evidence + corroboration + baseline
    criticality   = subtotal * (multiplier - 1)
    identity      = +5 when the source matches no inventory record
    score         = clamp(round(subtotal + criticality + identity), 0, 100)

Every term is returned as a named factor, so the factors sum to the score
(before clamping and rounding).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .behaviour import BaselineComparison
from .correlation import CorrelationGroup

RISK_MODEL_VERSION = "risk-1.0"


@dataclass(frozen=True)
class RiskModel:
    severity_points: dict[str, int] = field(default_factory=lambda: {
        "low": 20, "medium": 40, "high": 60, "critical": 80})
    corroboration_per_category: float = 15.0
    corroboration_cap: float = 30.0
    max_shared_evidence: float = 0.5      # above this share of common events, not independent
    baseline_adjustment: float = 10.0
    criticality_multiplier: dict[str, float] = field(default_factory=lambda: {
        "low": 0.8, "medium": 1.0, "high": 1.15, "critical": 1.3})
    unidentified_asset_points: float = 5.0
    levels: tuple[tuple[int, str], ...] = (
        (80, "critical"), (60, "high"), (40, "medium"), (20, "low"), (0, "informational"))


@dataclass(frozen=True)
class AssetContext:
    """Inventory metadata for the source. ``None`` means not known."""
    asset_id: str | None = None
    identified: bool = False
    criticality: str | None = None


@dataclass(frozen=True)
class RiskFactor:
    factor: str
    contribution: float
    detail: str


@dataclass(frozen=True)
class RiskAssessment:
    group_id: str
    source_ip: str
    risk_score: int
    risk_level: str
    detection_confidence: float
    max_severity: str | None
    asset_criticality: str | None
    asset_identified: bool
    corroborating_categories: int
    factors: tuple[RiskFactor, ...]
    missing_context: tuple[str, ...]
    explanation: str
    model_version: str = RISK_MODEL_VERSION

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["factors"] = [asdict(f) for f in self.factors]
        data["missing_context"] = list(self.missing_context)
        return data


def _level(score: int, model: RiskModel) -> str:
    return next(name for floor, name in model.levels if score >= floor)


def assess(group: CorrelationGroup, asset: AssetContext | None = None,
           baseline: BaselineComparison | None = None,
           model: RiskModel | None = None) -> RiskAssessment:
    model = model or RiskModel()
    asset = asset or AssetContext()
    factors: list[RiskFactor] = []
    missing: list[str] = []

    # Strongest detection per category; the overall strongest sets the base.
    best: dict[str, Any] = {}
    for detection in group.detections:
        points = model.severity_points.get(detection.severity, 0) * detection.confidence
        if detection.category not in best or points > best[detection.category][0]:
            best[detection.category] = (points, detection)

    if not best:
        return RiskAssessment(
            group_id=group.group_id, source_ip=group.source_ip, risk_score=0,
            risk_level="informational", detection_confidence=0.0, max_severity=None,
            asset_criticality=asset.criticality, asset_identified=asset.identified,
            corroborating_categories=0, factors=(), missing_context=("no_detections",),
            explanation="Insufficient evidence: no detection supports a risk assessment.")

    ranked = sorted(best.values(), key=lambda item: (-item[0], item[1].detection_id))
    lead_points, lead = ranked[0]
    factors.append(RiskFactor(
        f"evidence_{lead.category}", round(lead_points, 2),
        f"{lead.rule_id} severity {lead.severity} ({model.severity_points.get(lead.severity, 0)} points) "
        f"x confidence {lead.confidence}."))

    # A further indicator corroborates only if it rests on different events.
    # Two rules that fired on the same flows are one piece of evidence, not two.
    corroboration = 0.0
    counted = [lead]
    used_events = set(lead.supporting_events)
    for _, other in ranked[1:]:
        own = set(other.supporting_events)
        shared = len(own & used_events) / len(own) if own else 1.0
        if shared > model.max_shared_evidence:
            factors.append(RiskFactor(
                f"overlapping_evidence_{other.category}", 0.0,
                f"{other.rule_id} rests on the same events as an indicator already counted "
                f"({round(shared * 100)}% shared); it is not treated as independent corroboration."))
            continue
        counted.append(other)
        used_events |= own
        gain = max(0.0, min(model.corroboration_per_category * other.confidence,
                            model.corroboration_cap - corroboration))
        corroboration += gain
        factors.append(RiskFactor(
            f"corroboration_{other.category}", round(gain, 2),
            f"{other.rule_id} independently supports the finding (confidence {other.confidence})."))

    subtotal = lead_points + corroboration

    if baseline is None or baseline.status == "insufficient_baseline_data":
        missing.append("behavioural_baseline")
    elif baseline.status == "above_baseline":
        subtotal += model.baseline_adjustment
        factors.append(RiskFactor("above_behavioural_baseline", model.baseline_adjustment,
                                  baseline.explanation))
    else:
        subtotal -= model.baseline_adjustment
        factors.append(RiskFactor("within_behavioural_baseline", -model.baseline_adjustment,
                                  "Conflicting evidence: " + baseline.explanation))

    if asset.criticality in model.criticality_multiplier:
        multiplier = model.criticality_multiplier[asset.criticality]
        adjustment = subtotal * (multiplier - 1)
        if adjustment:
            factors.append(RiskFactor("asset_criticality", round(adjustment, 2),
                                      f"Asset criticality {asset.criticality} (multiplier {multiplier})."))
        subtotal += adjustment
    else:
        missing.append("asset_criticality")

    if not asset.identified:
        missing.append("asset_identity")
        subtotal += model.unidentified_asset_points
        factors.append(RiskFactor("unidentified_asset", model.unidentified_asset_points,
                                  "The source address matches no inventory record."))

    score = max(0, min(100, round(subtotal)))
    confidence = 1.0
    for detection in counted:
        confidence *= 1 - detection.confidence
    confidence = round(min(0.99, 1 - confidence), 2)
    max_severity = max((d.severity for _, d in ranked), key=lambda s: model.severity_points.get(s, 0))
    level = _level(score, model)

    names = ", ".join(sorted(best))
    gaps = f" Missing context: {', '.join(missing)}." if missing else ""
    return RiskAssessment(
        group_id=group.group_id, source_ip=group.source_ip, risk_score=score, risk_level=level,
        detection_confidence=confidence, max_severity=max_severity,
        asset_criticality=asset.criticality if asset.criticality in model.criticality_multiplier else None,
        asset_identified=asset.identified, corroborating_categories=len(counted),
        factors=tuple(factors), missing_context=tuple(missing),
        explanation=(f"Risk {score}/100 ({level}) for finding '{group.finding}', based on "
                     f"{len(counted)} independent indicator type(s) out of {len(best)} raised: {names}.{gaps}"))
