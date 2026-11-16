"""Seals every new audit entry into a hash chain and verifies the chain.

The seal is written in the same database transaction as the audit entry, by a
session hook, so no code path that adds an AuditLogRecord can forget it.
Entries written before this module existed have no seal; verification reports
them separately as "not covered" instead of pretending they are protected.
"""
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import event, insert, select
from sqlalchemy.orm import Session

from app.core.audit_chain import ALGORITHM, GENESIS, entry_hash, verify_chain
from app.db_models import AuditLogRecord
from app.platform_models import AuditSealRecord


def audit_payload(record: AuditLogRecord) -> dict[str, Any]:
    """The content a seal covers. Identical before storage and after reading back."""
    moment: datetime = record.occurred_at
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return {
        "audit_id": record.audit_id,
        "occurred_at": moment.astimezone(UTC).isoformat(),
        "actor": record.actor,
        "action": record.action,
        "target_type": record.target_type,
        "target_id": record.target_id,
        "details": record.details_json,
    }


@event.listens_for(Session, "after_flush")
def _seal_new_audit_entries(session: Session, flush_context: Any) -> None:
    fresh = sorted(
        (item for item in session.new if isinstance(item, AuditLogRecord) and item.audit_id is not None),
        key=lambda item: item.audit_id,
    )
    if not fresh:
        return

    table = AuditSealRecord.__table__
    connection = session.connection()
    previous = connection.execute(
        select(table.c.record_hash).order_by(table.c.audit_id.desc()).limit(1)
    ).scalar() or GENESIS

    for record in fresh:
        digest = entry_hash(previous, audit_payload(record))
        connection.execute(insert(table).values(
            audit_id=record.audit_id, previous_hash=previous, record_hash=digest, algorithm=ALGORITHM))
        previous = digest


def verify_audit_trail(db: Session) -> dict[str, Any]:
    seals = db.scalars(select(AuditSealRecord).order_by(AuditSealRecord.audit_id)).all()
    records = {row.audit_id: row for row in db.scalars(select(AuditLogRecord)).all()}

    result = verify_chain(
        (seal.audit_id,
         audit_payload(records[seal.audit_id]) if seal.audit_id in records else None,
         seal.previous_hash, seal.record_hash)
        for seal in seals
    )

    sealed = {seal.audit_id for seal in seals}
    first_sealed = min(sealed) if sealed else None
    not_covered = sorted(i for i in records if first_sealed is None or i < first_sealed)
    unsealed_inside = sorted(i for i in records if first_sealed is not None and i > first_sealed and i not in sealed)

    if result["valid"] and unsealed_inside:
        result.update(valid=False, first_invalid_audit_id=unsealed_inside[0],
                      reason="An entry inside the sealed range has no seal.")

    result.update(
        algorithm=ALGORITHM,
        total_entries=len(records),
        sealed_entries=len(seals),
        entries_not_covered=len(not_covered),
        first_sealed_audit_id=first_sealed,
        limitation=("The chain detects edits, removals and reordering of sealed entries. Removing the "
                    "newest entries is only detectable by comparing latest_hash with a value noted earlier."),
    )
    return result
