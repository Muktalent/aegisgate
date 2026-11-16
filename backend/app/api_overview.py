"""Security overview and asset inventory for the dashboard (AG-02, AG-05).

Every number is derived from persisted rows. Nothing here is estimated or
invented; values that do not exist yet are returned as null.
"""
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis_models import DetectionRecord, FindingRecord
from app.core.events import parse_utc
from app.core.response import simulated_target_state
from app.database import get_db
from app.db_models import AlertRecord, AuditLogRecord, IncidentCaseRecord
from app.platform_models import ResponseActionRecord
from asset_correlation import load_assets
from security import require_roles

router = APIRouter(prefix="/api/v1", tags=["overview"])

READ_ROLES = ("soc_analyst", "security_admin", "viewer")
LEVELS = ("critical", "high", "medium", "low", "informational")
SEVERITIES = ("critical", "high", "medium", "low")
OPEN_CASE_STATES = ("open", "acknowledged")


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _event_time(alert: AlertRecord) -> datetime | None:
    try:
        return parse_utc(alert.telemetry_json.get("timestamp"))
    except (ValueError, AttributeError):
        return None


def build_assets(db: Session) -> list[dict[str, Any]]:
    """Inventory assets plus every source address seen in telemetry that has
    no inventory record. Status is derived from current findings:
    at_risk (risk 60+), under_review (any other current finding), normal,
    or unknown (not in the inventory)."""
    alerts = db.scalars(select(AlertRecord)).all()
    findings = db.scalars(select(FindingRecord).where(FindingRecord.is_current.is_(True))).all()
    detections = db.scalars(select(DetectionRecord).where(DetectionRecord.is_current.is_(True))).all()

    seen: dict[str, dict[str, Any]] = {}
    for alert in alerts:
        entry = seen.setdefault(alert.source_ip, {"events": 0, "last_seen": None})
        entry["events"] += 1
        moment = _event_time(alert)
        if moment and (entry["last_seen"] is None or moment > entry["last_seen"]):
            entry["last_seen"] = moment

    in_effect: dict[str, list[str]] = {}
    for action in db.scalars(select(ResponseActionRecord).where(
            ResponseActionRecord.state == "executed_in_simulation")).all():
        in_effect.setdefault(action.source_ip, []).append(action.action_type)

    def row(address: str, asset: dict[str, Any] | None) -> dict[str, Any]:
        own = [f for f in findings if f.source_ip == address]
        highest = max((f.risk_score for f in own), default=None)
        if asset is None:
            status = "unknown"
        elif highest is not None and highest >= 60:
            status = "at_risk"
        elif own:
            status = "under_review"
        else:
            status = "normal"
        activity = seen.get(address, {"events": 0, "last_seen": None})
        return {
            "asset_id": asset.get("device_id") if asset else None,
            "ip_address": address,
            "device_name": asset.get("device_name") if asset else None,
            "user_id": asset.get("user_id") if asset else None,
            "location": asset.get("location") if asset else None,
            "criticality": (str(asset.get("resource_sensitivity") or "").lower() or None) if asset else None,
            "identified": asset is not None,
            "status": status,
            "event_count": activity["events"],
            "detection_count": sum(1 for d in detections if d.source_ip == address),
            "finding_count": len(own),
            "highest_risk": highest,
            "last_seen": activity["last_seen"].isoformat() if activity["last_seen"] else None,
            "simulated_state": simulated_target_state(in_effect.get(address, [])),
        }

    inventory = {a["ip_address"]: a for a in load_assets()
                 if isinstance(a, dict) and isinstance(a.get("ip_address"), str)}
    rows = [row(address, asset) for address, asset in sorted(inventory.items())]
    rows += [row(address, None) for address in sorted(seen) if address not in inventory]
    return rows


@router.get("/assets")
def list_assets(db: Session = Depends(get_db),
                identity: dict = Depends(require_roles(*READ_ROLES))) -> dict:
    rows = build_assets(db)
    return {"total": len(rows), "items": rows}


@router.get("/dashboard/overview")
def overview(db: Session = Depends(get_db),
             identity: dict = Depends(require_roles(*READ_ROLES))) -> dict:
    alerts = db.scalars(select(AlertRecord)).all()
    findings = db.scalars(select(FindingRecord).where(FindingRecord.is_current.is_(True))).all()
    detections = db.scalars(select(DetectionRecord).where(DetectionRecord.is_current.is_(True))).all()
    cases = db.scalars(select(IncidentCaseRecord)).all()
    assets = build_assets(db)
    last_run = db.scalars(select(AuditLogRecord).where(AuditLogRecord.action == "analysis_run")
                          .order_by(AuditLogRecord.audit_id.desc()).limit(1)).first()

    by_level = {level: 0 for level in LEVELS}
    for finding in findings:
        by_level[finding.risk_level] = by_level.get(finding.risk_level, 0) + 1

    top = max(findings, key=lambda f: (f.risk_score, f.group_id), default=None)

    by_status = {"normal": 0, "under_review": 0, "at_risk": 0, "unknown": 0}
    for asset in assets:
        by_status[asset["status"]] += 1

    # Hourly detection counts for the 24 hours that end at the latest detection.
    trend: list[dict[str, Any]] = []
    if detections:
        latest = max(_utc(d.window_start) for d in detections)
        end = latest.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        buckets = {end - timedelta(hours=24 - i): {s: 0 for s in SEVERITIES} for i in range(24)}
        for detection in detections:
            hour = _utc(detection.window_start).replace(minute=0, second=0, microsecond=0)
            if hour in buckets and detection.severity in SEVERITIES:
                buckets[hour][detection.severity] += 1
        trend = [{"hour": hour.isoformat(), **counts} for hour, counts in sorted(buckets.items())]

    names = {a["ip_address"]: a["device_name"] for a in assets}
    timed = [(moment, alert) for alert in alerts if (moment := _event_time(alert)) is not None]
    timed.sort(key=lambda pair: (pair[0], pair[1].event_id), reverse=True)
    recent = [{
        "event_id": alert.event_id, "timestamp": moment.isoformat(), "source": alert.source,
        "event_type": alert.event_type, "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "destination_port": alert.telemetry_json.get("destination_port"),
        "signature": alert.signature if alert.event_type == "alert" else None,
        "asset_name": names.get(alert.source_ip),
    } for moment, alert in timed[:8]]

    return {
        "academic_mode": True,
        "generated_at": datetime.now(UTC).isoformat(),
        "counts": {
            "monitored_assets": sum(1 for a in assets if a["identified"]),
            "unidentified_sources": by_status["unknown"],
            "events": len(alerts),
            "current_detections": len(detections),
            "current_findings": len(findings),
            "open_investigations": sum(1 for c in cases if c.status in OPEN_CASE_STATES),
            "response_actions": len(db.scalars(select(ResponseActionRecord).where(
                ResponseActionRecord.state == "executed_in_simulation")).all()),
        },
        "findings_by_level": by_level,
        "highest_risk": None if top is None else {
            "group_id": top.group_id, "risk_score": top.risk_score, "risk_level": top.risk_level,
            "finding": top.finding, "source_ip": top.source_ip},
        "attention": {
            "high_severity_detections": sum(1 for d in detections if d.severity in ("high", "critical")),
            "findings_awaiting_review": sum(1 for f in findings if f.decision == "manual_review"),
            "unidentified_sources": by_status["unknown"],
            "restrictive_recommendations": sum(
                1 for f in findings if f.decision in ("step_up_authentication", "deny")),
        },
        "detection_trend": trend,
        "recent_events": recent,
        "assets_by_status": by_status,
        "system": {
            "api": "ok", "database": "ok",
            "last_analysis_at": _utc(last_run.occurred_at).isoformat() if last_run else None,
        },
    }
