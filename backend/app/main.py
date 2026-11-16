import json
import sys
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import Base, engine, get_db
from app.db_models import (
    AlertRecord,
    AuditLogRecord,
    IncidentCaseRecord,
)
from app.schemas import (
    CreateCaseRequest,
    HealthResponse,
    IncidentCaseResponse,
    InvestigationResponse,
    ProcessedEventResponse,
    SimulationRequest,
    UpdateCaseRequest,
)
from security import require_roles
BACKEND_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BACKEND_DIR.parents[0]
DATA_DIR = PROJECT_ROOT / "data"
TELEMETRY_DIR = DATA_DIR / "telemetry"

if str(BACKEND_DIR) not in sys.path:
    sys.path.append(str(BACKEND_DIR))

from app.ingestion import normalise_event  # noqa: E402


@asynccontextmanager
async def lifespan(
    app: FastAPI,
) -> AsyncIterator[None]:
    Base.metadata.create_all(bind=engine)

    yield


app = FastAPI(
    title="AegisGate API",
    version="0.1.0",
    description=(
        "Laboratory API for telemetry processing, explainable risk "
        "assessment, investigation, and safe response simulation."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Content-Type"],
)


# Analysis core (detections, findings, risk, policy) under /api/v1.
from app.api_analysis import router as analysis_router  # noqa: E402

app.include_router(analysis_router)

# Sign-in, sessions and user administration under /api/v1.
from app.api_auth import router as auth_router  # noqa: E402

app.include_router(auth_router)

# Dashboard overview and asset inventory under /api/v1.
from app.api_overview import router as overview_router  # noqa: E402

app.include_router(overview_router)

# Simulated responses, audit trail and Demo Lab under /api/v1.
from app.api_platform import router as platform_router  # noqa: E402

app.include_router(platform_router)

# Telemetry file import, evaluation and CSV reports under /api/v1.
from app.api_ingest import router as ingest_router  # noqa: E402
from app.api_reports import router as reports_router  # noqa: E402
from app.api_allowlist import router as allowlist_router  # noqa: E402

app.include_router(ingest_router)
app.include_router(reports_router)
app.include_router(allowlist_router)

SCENARIOS = {
    "suricata_c2": "suricata_eve_sample.json",
    "zeek_dns_c2": "zeek_dns_sample.json",
    "zeek_notice_c2": "zeek_notice_sample.json",
    "unknown_asset": "suricata_unknown_asset_sample.json",
}





def write_audit_log(
    db: Session,
    *,
    action: str,
    target_type: str,
    target_id: str,
    details: dict,
    actor: str = "system",
) -> None:
    db.add(
        AuditLogRecord(
            occurred_at=datetime.now(UTC),
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            details_json=details,
        )
    )


def process_and_store(
    raw_event: dict,
    db: Session,
    commit: bool = True,
) -> dict:
    """Normalise, correlate with the inventory and store one raw event. No
    risk decision is made here (see ``app.ingestion``). With ``commit=False``
    the caller commits, so a whole file is stored in one transaction."""
    try:
        result = normalise_event(raw_event)
    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error

    event_id = str(uuid4())
    telemetry = result["telemetry"]
    connection_event = result.get("connection_event")
    risk_assessment = result.get("risk_assessment")
    access_decision = result["access_decision"]

    alert = AlertRecord(
        event_id=event_id,
        received_at=datetime.now(UTC),
        status=result["status"],
        source=telemetry["source"],
        event_type=telemetry["event_type"],
        source_ip=telemetry["source_ip"],
        destination_ip=telemetry.get("destination_ip"),
        signature=telemetry.get("signature"),
        indicator=telemetry.get("indicator"),
        severity=telemetry["severity"],
        is_malicious=telemetry["is_malicious"],
        asset_id=(
            connection_event.get("device_id")
            if connection_event
            else None
        ),
        user_id=(
            connection_event.get("user_id")
            if connection_event
            else None
        ),
        device_name=(
            connection_event.get("device_name")
            if connection_event
            else None
        ),
        risk_score=(
            risk_assessment.get("score")
            if risk_assessment
            else None
        ),
        access_action=access_decision["action"],
        telemetry_json=telemetry,
        connection_event_json=connection_event,
        risk_assessment_json=risk_assessment,
        access_decision_json=access_decision,
        error=result.get("error"),
    )

    db.add(alert)

    write_audit_log(
        db,
        action="telemetry_ingested",
        target_type="alert",
        target_id=event_id,
        details={
            "source": telemetry["source"],
            "event_type": telemetry["event_type"],
            "source_ip": telemetry["source_ip"],
            "status": result["status"],
            "access_action": access_decision["action"],
        },
    )

    if commit:
        db.commit()
        db.refresh(alert)
    else:
        db.flush()

    return {
        "event_id": alert.event_id,
        "status": alert.status,
        "telemetry": alert.telemetry_json,
        "connection_event": alert.connection_event_json,
        "risk_assessment": alert.risk_assessment_json,
        "access_decision": alert.access_decision_json,
        "error": alert.error,
    }


@app.get(
    "/health",
    response_model=HealthResponse,
)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        service="aegisgate-api",
        version="0.1.0",
    )


@app.post(
    "/v1/telemetry/events",
    response_model=ProcessedEventResponse,
)
def ingest_telemetry_event(
    raw_event: dict,
    db: Session = Depends(get_db),
    identity: dict = Depends(
        require_roles(
            "ingestor",
            "security_admin",
        )
    ),
) -> ProcessedEventResponse:
    return ProcessedEventResponse(
        **process_and_store(raw_event, db)
    )
@app.post(
    "/v1/simulation/events",
    response_model=ProcessedEventResponse,
)
def simulate_event(
    request: SimulationRequest,
    db: Session = Depends(get_db),
    identity: dict = Depends(
        require_roles(
            "ingestor",
            "security_admin",
        )
    ),
) -> ProcessedEventResponse:
    filename = SCENARIOS.get(request.scenario)

    if filename is None:
        allowed = ", ".join(sorted(SCENARIOS))
        raise HTTPException(
            status_code=422,
            detail=f"Unsupported scenario. Allowed: {allowed}.",
        )

    sample_path = TELEMETRY_DIR / filename

    if not sample_path.exists():
        raise HTTPException(
            status_code=500,
            detail=f"Sample telemetry file is missing: {filename}.",
        )

    raw_event = json.loads(
        sample_path.read_text(encoding="utf-8")
    )

    return ProcessedEventResponse(
        **process_and_store(raw_event, db)
    )


@app.get(
    "/v1/events",
    response_model=list[ProcessedEventResponse],
)
def list_events(
    db: Session = Depends(get_db),
    identity: dict = Depends(
        require_roles(
            "soc_analyst",
            "security_admin",
        )
    ),
) -> list[ProcessedEventResponse]:
    statement = select(AlertRecord).order_by(
        AlertRecord.received_at.desc()
    )

    alerts = db.scalars(statement).all()

    return [
        ProcessedEventResponse(
            event_id=alert.event_id,
            status=alert.status,
            telemetry=alert.telemetry_json,
            connection_event=alert.connection_event_json,
            risk_assessment=alert.risk_assessment_json,
            access_decision=alert.access_decision_json,
            error=alert.error,
        )
        for alert in alerts
    ]


@app.get(
    "/v1/investigations/ip/{ip_address}",
    response_model=InvestigationResponse,
)
def investigate_ip(
    ip_address: str,
    db: Session = Depends(get_db),
    identity: dict = Depends(
        require_roles(
            "soc_analyst",
            "security_admin",
        )
    ),
) -> InvestigationResponse:
    statement = (
        select(AlertRecord)
        .where(AlertRecord.source_ip == ip_address)
        .order_by(AlertRecord.received_at.asc())
    )

    matches = db.scalars(statement).all()

    write_audit_log(
        db,
        action="ip_investigation_requested",
        target_type="ip_address",
        target_id=ip_address,
        details={
            "local_evidence_count": len(matches),
            "scope": "local_aegisgate_evidence_only",
        },
        actor=identity["username"],
    )

    db.commit()

    if not matches:
        raise HTTPException(
            status_code=404,
            detail=(
                "No local AegisGate evidence exists for this IP yet. "
                "Inject or ingest telemetry before investigating it."
            ),
        )

    timestamps = [
        alert.telemetry_json["timestamp"]
        for alert in matches
    ]

    assets = sorted(
        {
            alert.device_name
            for alert in matches
            if alert.device_name
        }
    )

    destinations = sorted(
        {
            alert.destination_ip
            for alert in matches
            if alert.destination_ip
        }
    )

    signatures = sorted(
        {
            alert.signature
            for alert in matches
            if alert.signature
        }
    )

    return InvestigationResponse(
        indicator=ip_address,
        indicator_type="ip",
        first_seen=min(timestamps),
        last_seen=max(timestamps),
        alert_count=len(matches),
        affected_assets=assets,
        observed_destinations=destinations,
        signatures=signatures,
        note=(
            "This result uses persisted local AegisGate evidence only. "
            "External passive enrichment will be added through auditable "
            "Threat Intelligence & Investigation providers."
        ),
    )

@app.post(
    "/v1/events/{event_id}/case",
    response_model=IncidentCaseResponse,
)
def create_case(
    event_id: str,
    request: CreateCaseRequest,
    db: Session = Depends(get_db),
    identity: dict = Depends(
        require_roles(
            "soc_analyst",
            "security_admin",
        )
    ),
) -> IncidentCaseResponse:
    alert = db.get(AlertRecord, event_id)

    if alert is None:
        raise HTTPException(
            status_code=404,
            detail=f"No alert found for event_id '{event_id}'.",
        )

    existing_case = db.scalar(
        select(IncidentCaseRecord).where(
            IncidentCaseRecord.alert_event_id == event_id
        )
    )

    if existing_case is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                "A case already exists for "
                f"event_id '{event_id}'."
            ),
        )

    now = datetime.now(UTC)

    case = IncidentCaseRecord(
        case_id=str(uuid4()),
        alert_event_id=event_id,
        status="open",
        title=request.title,
        analyst_note=request.analyst_note,
        created_at=now,
        updated_at=now,
        created_by=identity["username"],
        updated_by=identity["username"],
    )

    db.add(case)

    write_audit_log(
        db,
        action="incident_case_created",
        target_type="incident_case",
        target_id=case.case_id,
        details={
            "alert_event_id": event_id,
            "status": case.status,
            "title": case.title,
        },
        actor=identity["username"],
    )

    db.commit()
    db.refresh(case)

    return IncidentCaseResponse(
        case_id=case.case_id,
        alert_event_id=case.alert_event_id,
        status=case.status,
        title=case.title,
        analyst_note=case.analyst_note,
        created_at=case.created_at,
        updated_at=case.updated_at,
        created_by=case.created_by,
        updated_by=case.updated_by,
    )


@app.get(
    "/v1/cases",
    response_model=list[IncidentCaseResponse],
)
def list_cases(
    status_filter: str | None = None,
    db: Session = Depends(get_db),
    identity: dict = Depends(
        require_roles(
            "soc_analyst",
            "security_admin",
        )
    ),
) -> list[IncidentCaseResponse]:
    statement = select(IncidentCaseRecord).order_by(
        IncidentCaseRecord.updated_at.desc()
    )

    if status_filter is not None:
        allowed_statuses = {
            "open",
            "acknowledged",
            "resolved",
            "false_positive",
        }

        if status_filter not in allowed_statuses:
            raise HTTPException(
                status_code=422,
                detail="Unsupported case status filter.",
            )

        statement = statement.where(
            IncidentCaseRecord.status == status_filter
        )

    cases = db.scalars(statement).all()

    return [
        IncidentCaseResponse(
            case_id=case.case_id,
            alert_event_id=case.alert_event_id,
            status=case.status,
            title=case.title,
            analyst_note=case.analyst_note,
            created_at=case.created_at,
            updated_at=case.updated_at,
            created_by=case.created_by,
            updated_by=case.updated_by,
        )
        for case in cases
    ]


@app.patch(
    "/v1/cases/{case_id}",
    response_model=IncidentCaseResponse,
)
def update_case(
    case_id: str,
    request: UpdateCaseRequest,
    db: Session = Depends(get_db),
    identity: dict = Depends(
        require_roles(
            "soc_analyst",
            "security_admin",
        )
    ),
) -> IncidentCaseResponse:
    case = db.get(IncidentCaseRecord, case_id)

    if case is None:
        raise HTTPException(
            status_code=404,
            detail=f"No incident case found for case_id '{case_id}'.",
        )

    previous_status = case.status

    case.status = request.status
    case.analyst_note = request.analyst_note
    case.updated_at = datetime.now(UTC)
    case.updated_by = identity["username"]

    write_audit_log(
        db,
        action="incident_case_updated",
        target_type="incident_case",
        target_id=case.case_id,
        details={
            "previous_status": previous_status,
            "new_status": case.status,
            "alert_event_id": case.alert_event_id,
        },
        actor=identity["username"],
    )

    db.commit()
    db.refresh(case)

    return IncidentCaseResponse(
        case_id=case.case_id,
        alert_event_id=case.alert_event_id,
        status=case.status,
        title=case.title,
        analyst_note=case.analyst_note,
        created_at=case.created_at,
        updated_at=case.updated_at,
        created_by=case.created_by,
        updated_by=case.updated_by,
    )
