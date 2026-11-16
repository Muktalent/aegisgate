"""Runs the analysis core over persisted telemetry and stores the results."""
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.api_allowlist import active_entries
from app.analysis_models import DetectionRecord, FindingRecord
from app.core.events import CanonicalEvent, event_from_stored_telemetry
from app.core.pipeline import analyse
from app.core.risk import AssetContext
from app.db_models import AlertRecord, AuditLogRecord
from asset_correlation import load_assets

GLOBAL_SCOPE = "all-events"


def asset_contexts() -> dict[str, AssetContext]:
    """Inventory metadata by IP address. The inventory field
    ``resource_sensitivity`` is used as the asset's criticality."""
    contexts: dict[str, AssetContext] = {}
    for asset in load_assets():
        address = asset.get("ip_address")
        if not isinstance(address, str) or not address:
            continue
        level = str(asset.get("resource_sensitivity") or "").lower() or None
        contexts[address] = AssetContext(
            asset_id=asset.get("device_id"), identified=True, criticality=level)
    return contexts


def load_events(db: Session, run_id: str | None) -> tuple[list[CanonicalEvent], list[CanonicalEvent], int]:
    """Return (events in scope, earlier events usable as history, skipped)."""
    current: list[CanonicalEvent] = []
    others: list[CanonicalEvent] = []
    skipped = 0
    for record in db.scalars(select(AlertRecord)).all():
        try:
            event = event_from_stored_telemetry(record.event_id, record.telemetry_json)
        except (ValueError, TypeError, AttributeError):
            skipped += 1
            continue
        if run_id is None:
            # Laboratory runs are analysed only inside their own run, so the
            # same synthetic activity is never reported twice.
            if event.run_id is None:
                current.append(event)
        elif event.run_id == run_id:
            current.append(event)
        else:
            others.append(event)
    if not current:
        return current, [], skipped
    first = min(event.timestamp for event in current)
    return current, [event for event in others if event.timestamp < first], skipped


def run_analysis(db: Session, *, actor: str, run_id: str | None = None) -> dict[str, Any]:
    scope = run_id or GLOBAL_SCOPE
    events, history, skipped = load_events(db, run_id)
    assets = asset_contexts()
    result = analyse(events, assets, history, allowlist=active_entries(db))
    now = datetime.now(UTC)

    # Earlier results of this scope stay stored but are no longer current.
    db.execute(update(DetectionRecord).where(DetectionRecord.scope == scope).values(is_current=False))
    db.execute(update(FindingRecord).where(FindingRecord.scope == scope).values(is_current=False))

    for item in result.findings:
        group = item.group
        for detection in group.detections:
            row = db.get(DetectionRecord, detection.detection_id)
            new_row = row is None
            if new_row:
                row = DetectionRecord(detection_id=detection.detection_id, created_at=now)
            row.scope = scope
            row.is_current = True
            row.group_id = group.group_id
            row.rule_id = detection.rule_id
            row.rule_version = detection.rule_version
            row.category = detection.category
            row.source_ip = detection.source_ip
            row.severity = detection.severity
            row.confidence = detection.confidence
            row.window_start = detection.window_start
            row.window_end = detection.window_end
            row.explanation = detection.explanation
            row.detail_json = detection.to_dict()
            row.updated_at = now
            if new_row:
                db.add(row)

        finding = db.get(FindingRecord, group.group_id)
        new_finding = finding is None
        if new_finding:
            finding = FindingRecord(group_id=group.group_id, created_at=now)
        finding.scope = scope
        finding.is_current = True
        finding.finding = group.finding
        finding.source_ip = group.source_ip
        finding.asset_id = (assets.get(group.source_ip) or AssetContext()).asset_id
        finding.window_start = group.window_start
        finding.window_end = group.window_end
        finding.risk_score = item.assessment.risk_score
        finding.risk_level = item.assessment.risk_level
        finding.detection_confidence = item.assessment.detection_confidence
        finding.decision = item.decision.decision
        finding.detail_json = item.to_dict()
        finding.versions_json = result.versions
        finding.updated_at = now
        if new_finding:
            db.add(finding)

    summary = {
        "scope": scope,
        "run_id": run_id,
        "events_analysed": result.event_count,
        "history_events": len(history),
        "events_skipped": skipped,
        "detection_count": len(result.detections),
        "finding_count": len(result.findings),
        "suppressed_count": len(result.suppressed),
        "suppressed": [{"detection_id": s.detection.detection_id, "rule_id": s.detection.rule_id,
                        "category": s.detection.category, "source_ip": s.detection.source_ip,
                        "entry_id": s.entry_id, "reason": s.reason} for s in result.suppressed],
        "detections_by_rule": _count(d.rule_id for d in result.detections),
        "findings_by_decision": _count(f.decision.decision for f in result.findings),
        "versions": result.versions,
        "completed_at": now.isoformat(),
    }
    db.add(AuditLogRecord(
        occurred_at=now, actor=actor, action="analysis_run", target_type="analysis_scope",
        target_id=scope, details_json=summary))
    db.commit()
    return summary


def _count(values) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))
