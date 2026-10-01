from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class ResourceSensitivity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RequestedAction(str, Enum):
    VIEW_CUSTOMER_RECORDS = "view_customer_records"
    EXPORT_DATA = "export_data"
    DELETE_RECORDS = "delete_records"
    CHANGE_BANK_DETAILS = "change_bank_details"


class EndpointHealth(str, Enum):
    HEALTHY = "healthy"
    UNKNOWN = "unknown"
    SUSPICIOUS = "suspicious"
    INFECTED = "infected"


class ConnectionEvent(BaseModel):
    event_id: str = Field(min_length=1)
    timestamp: datetime
    user_id: str = Field(min_length=3)
    device_id: str = Field(min_length=3)
    device_name: str = Field(min_length=3)

    managed_device: bool
    device_compliant: bool
    mfa_success: bool

    location: str = Field(min_length=2)
    known_location: bool
    usual_hours: bool

    resource: str = Field(min_length=2)
    resource_sensitivity: ResourceSensitivity
    requested_action: RequestedAction

    failed_logins_24h: int = Field(ge=0)
    endpoint_health: EndpointHealth
    infection_signal: bool