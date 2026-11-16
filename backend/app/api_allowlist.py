"""Approved-activity allowlist under /api/v1/allowlist."""
import secrets
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.allowlist import ALLOWABLE_CATEGORIES, AllowEntry
from app.database import get_db
from app.db_models import AuditLogRecord
from app.platform_models import AllowlistEntryRecord
from security import require_roles

router = APIRouter(prefix="/api/v1/allowlist", tags=["allowlist"])

READ_ROLES = ("soc_analyst", "security_admin", "viewer")
ADMIN_ROLES = ("security_admin",)


class AllowlistCreate(BaseModel):
    source_ip: str = Field(min_length=3, max_length=64)
    destinations: list[str] = Field(min_length=1, max_length=20)
    ports: list[int] = Field(default_factory=list, max_length=20)
    categories: list[str] = Field(min_length=1, max_length=len(ALLOWABLE_CATEGORIES))
    reason: str = Field(min_length=5, max_length=500)


class AllowlistDisable(BaseModel):
    note: str = Field(min_length=3, max_length=500)


def to_entry(row: AllowlistEntryRecord) -> AllowEntry:
    return AllowEntry(entry_id=row.entry_id, source_ip=row.source_ip,
                      destinations=tuple(row.destinations_json), ports=tuple(row.ports_json),
                      categories=tuple(row.categories_json), reason=row.reason)


def active_entries(db: Session) -> list[AllowEntry]:
    rows = db.scalars(select(AllowlistEntryRecord).where(AllowlistEntryRecord.active == 1)).all()
    return [to_entry(row) for row in rows]


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return (value if value.tzinfo else value.replace(tzinfo=UTC)).isoformat()


def _view(row: AllowlistEntryRecord) -> dict[str, Any]:
    return {
        "entry_id": row.entry_id, "source_ip": row.source_ip, "destinations": row.destinations_json,
        "ports": row.ports_json, "categories": row.categories_json, "reason": row.reason,
        "active": bool(row.active), "created_by": row.created_by, "created_at": _iso(row.created_at),
        "disabled_by": row.disabled_by, "disabled_at": _iso(row.disabled_at), "disabled_note": row.disabled_note,
    }


@router.get("")
def list_allowlist(db: Session = Depends(get_db),
                   identity: dict = Depends(require_roles(*READ_ROLES))) -> dict:
    rows = db.scalars(select(AllowlistEntryRecord).order_by(AllowlistEntryRecord.created_at.desc())).all()
    return {"items": [_view(r) for r in rows], "categories": list(ALLOWABLE_CATEGORIES)}


@router.post("", status_code=201)
def create_entry(body: AllowlistCreate, db: Session = Depends(get_db),
                 identity: dict = Depends(require_roles(*ADMIN_ROLES))) -> dict:
    entry_id = f"AL-{secrets.token_hex(4)}"
    destinations = [d.strip() for d in body.destinations if d.strip()]
    try:
        entry = AllowEntry(entry_id=entry_id, source_ip=body.source_ip.strip(), destinations=tuple(destinations),
                           ports=tuple(sorted(set(body.ports))), categories=tuple(sorted(set(body.categories))),
                           reason=body.reason.strip())
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    now = datetime.now(UTC)
    row = AllowlistEntryRecord(
        entry_id=entry_id, source_ip=entry.source_ip, destinations_json=list(entry.destinations),
        ports_json=list(entry.ports), categories_json=list(entry.categories), reason=entry.reason,
        active=1, created_by=identity["username"][:128], created_at=now)
    db.add(row)
    db.add(AuditLogRecord(occurred_at=now, actor=identity["username"][:128], action="allowlist_entry_created",
                          target_type="allowlist_entry", target_id=entry_id, details_json=entry.to_dict()))
    db.commit()
    return _view(row)


@router.post("/{entry_id}/disable")
def disable_entry(entry_id: str, body: AllowlistDisable, db: Session = Depends(get_db),
                  identity: dict = Depends(require_roles(*ADMIN_ROLES))) -> dict:
    row = db.get(AllowlistEntryRecord, entry_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Allowlist entry not found.")
    if not row.active:
        raise HTTPException(status_code=409, detail="The entry is already disabled.")
    now = datetime.now(UTC)
    row.active, row.disabled_by, row.disabled_at, row.disabled_note = 0, identity["username"][:128], now, body.note
    db.add(AuditLogRecord(occurred_at=now, actor=identity["username"][:128], action="allowlist_entry_disabled",
                          target_type="allowlist_entry", target_id=entry_id, details_json={"note": body.note}))
    db.commit()
    return _view(row)
