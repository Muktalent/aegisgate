from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


class ProcessedEventResponse(BaseModel):
    event_id: str | None = None
    status: str
    telemetry: dict[str, Any]
    connection_event: dict[str, Any] | None = None
    risk_assessment: dict[str, Any] | None = None
    access_decision: dict[str, Any]
    error: str | None = None


class SimulationRequest(BaseModel):
    scenario: str = Field(
        description=(
            "Laboratory scenario: suricata_c2, zeek_dns_c2, "
            "zeek_notice_c2, or unknown_asset."
        )
    )


class InvestigationResponse(BaseModel):
    indicator: str
    indicator_type: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    alert_count: int
    affected_assets: list[str]
    observed_destinations: list[str]
    signatures: list[str]
    note: str


class CreateCaseRequest(BaseModel):
    title: str = Field(
        min_length=3,
        max_length=255,
    )
    analyst_note: str | None = Field(
        default=None,
        max_length=4000,
    )


class UpdateCaseRequest(BaseModel):
    status: str = Field(
        pattern="^(acknowledged|resolved|false_positive)$"
    )
    analyst_note: str = Field(
        min_length=3,
        max_length=4000,
    )


class IncidentCaseResponse(BaseModel):
    case_id: str
    alert_event_id: str
    status: str
    title: str
    analyst_note: str | None
    created_at: datetime
    updated_at: datetime
    created_by: str
    updated_by: str

class DashboardSummaryResponse(BaseModel):
    total_alerts: int
    open_cases: int
    critical_alerts: int
    denied_events: int
    unresolved_assets: int
    alerts_by_source: dict[str, int]
    cases_by_status: dict[str, int]