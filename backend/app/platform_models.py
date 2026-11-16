"""Persistence for simulated responses, the audit seal chain and Demo Lab runs."""
from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class ResponseActionRecord(Base):
    __tablename__ = "response_actions"

    action_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    group_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    asset_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    impact: Mapped[str] = mapped_column(String(16), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    requested_by: Mapped[str] = mapped_column(String(128), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    outcome_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    history_json: Mapped[list] = mapped_column(JSON, nullable=False)


class AuditSealRecord(Base):
    """One row per sealed audit entry: the hash chain of app.core.audit_chain."""
    __tablename__ = "audit_seals"

    audit_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False)


class DemoRunRecord(Base):
    __tablename__ = "demo_runs"

    run_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    scenario_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    started_by: Mapped[str] = mapped_column(String(128), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    result_json: Mapped[dict] = mapped_column(JSON, nullable=False)


class TelemetryImportRecord(Base):
    """One uploaded telemetry file and what happened to its records."""
    __tablename__ = "telemetry_imports"

    import_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    imported_by: Mapped[str] = mapped_column(String(128), nullable=False)
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    result_json: Mapped[dict] = mapped_column(JSON, nullable=False)


class EventFingerprintRecord(Base):
    """SHA-256 of each imported raw record, so a re-imported record is skipped."""
    __tablename__ = "event_fingerprints"

    fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    import_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)


class AllowlistEntryRecord(Base):
    """Approved benign activity (app.core.allowlist). Entries are disabled,
    never deleted, so every past suppression stays explainable."""
    __tablename__ = "allowlist_entries"

    entry_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    destinations_json: Mapped[list] = mapped_column(JSON, nullable=False)
    ports_json: Mapped[list] = mapped_column(JSON, nullable=False)
    categories_json: Mapped[list] = mapped_column(JSON, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    active: Mapped[int] = mapped_column(Integer, nullable=False, default=1, index=True)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    disabled_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_note: Mapped[str | None] = mapped_column(Text, nullable=True)
