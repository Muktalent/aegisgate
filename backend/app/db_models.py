from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class AlertRecord(Base):
    __tablename__ = "alerts"

    event_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
    )

    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )

    source: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )

    event_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    source_ip: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    destination_ip: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    signature: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    indicator: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    severity: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    is_malicious: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
    )

    asset_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        index=True,
    )

    user_id: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    device_name: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    risk_score: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        index=True,
    )

    access_action: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    telemetry_json: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
    )

    connection_event_json: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    risk_assessment_json: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    access_decision_json: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
    )

    error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )


class AuditLogRecord(Base):
    __tablename__ = "audit_log"

    audit_id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    actor: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    action: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )

    target_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    target_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    details_json: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
    )
class IncidentCaseRecord(Base):
    __tablename__ = "incident_cases"

    case_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
    )

    alert_event_id: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        unique=True,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    analyst_note: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    created_by: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    updated_by: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )