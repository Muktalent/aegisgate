"""Tamper-evident audit trail (AG-12): a SHA-256 hash chain.

Each entry's hash covers its own content and the previous entry's hash, so
editing, removing or reordering a covered entry breaks every later hash.
The chain detects tampering; it does not prevent it, and someone who can
rewrite the whole table could rebuild the chain. Periodic external
checkpoints of the latest hash are the documented mitigation.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

GENESIS = "0" * 64
ALGORITHM = "sha256-chain-v1"


def canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      default=str).encode("utf-8")


def entry_hash(previous_hash: str, record: dict[str, Any]) -> str:
    return hashlib.sha256(previous_hash.encode("ascii") + b"\n" + canonical(record)).hexdigest()


def verify_chain(entries: Iterable[tuple[int, dict[str, Any] | None, str, str]]) -> dict[str, Any]:
    """``entries`` are (audit_id, record or None if the audit row is missing,
    stored previous_hash, stored record_hash) in ascending audit_id order."""
    previous = GENESIS
    checked = 0
    for audit_id, record, stored_previous, stored_hash in entries:
        checked += 1
        if record is None:
            return {"valid": False, "checked": checked, "first_invalid_audit_id": audit_id,
                    "reason": "The audit entry is missing."}
        if stored_previous != previous:
            return {"valid": False, "checked": checked, "first_invalid_audit_id": audit_id,
                    "reason": "The link to the previous entry is broken (an entry was removed or reordered)."}
        if entry_hash(previous, record) != stored_hash:
            return {"valid": False, "checked": checked, "first_invalid_audit_id": audit_id,
                    "reason": "The entry content does not match its recorded hash."}
        previous = stored_hash
    return {"valid": True, "checked": checked, "first_invalid_audit_id": None,
            "reason": None, "latest_hash": previous if checked else None}
