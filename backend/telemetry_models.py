from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class NetworkTelemetryEvent(BaseModel):
    source: str = Field(
        description="Sensor type, for example suricata or zeek."
    )
    event_type: str = Field(
        description="Normalized type: alert, dns, connection, notice, tls, or http."
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
    raw_event: dict[str, Any]