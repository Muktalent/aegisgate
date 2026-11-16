from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, StrictBool, StrictInt


class LabMetadata(BaseModel):
    synthetic: StrictBool
    scenario: str = Field(min_length=1, max_length=100)
    sequence: StrictInt = Field(ge=1)
    run_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )


class NetworkTelemetryEvent(BaseModel):
    source: str = Field(
        description="Sensor type, for example suricata or zeek."
    )
    event_type: str = Field(
        description=(
            "Normalized type: alert, dns, connection, notice, tls, or http."
        )
    )
    timestamp: datetime
    source_ip: str = Field(min_length=3)
    destination_ip: str | None = None
    destination_port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | None = None

    severity: int = Field(
        default=3,
        ge=1,
        le=5,
        description="1 is highest severity and 5 is informational.",
    )
    signature: str | None = None
    category: str | None = None
    indicator: str | None = None
    is_malicious: bool = False

    # Observed values only; None when the sensor did not report them.
    bytes_out: int | None = Field(default=None, ge=0)
    bytes_in: int | None = Field(default=None, ge=0)
    signature_id: int | None = Field(default=None, ge=0)

    lab_metadata: LabMetadata | None = Field(
        default=None,
        description=(
            "Caller-declared laboratory metadata. "
            "Not verified provenance and not an authorization signal."
        ),
    )

    raw_event: dict[str, Any]
