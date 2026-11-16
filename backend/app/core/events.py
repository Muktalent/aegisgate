"""Canonical event model shared by every analysis stage.

Unknown values stay ``None``. Nothing here invents defaults for fields the
sensor did not report.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = "canonical-event-1.0"

# RFC 1918 and loopback/link-local. Documentation ranges such as
# 198.51.100.0/24 are deliberately NOT internal: the laboratory datasets use
# them to stand for external hosts.
DEFAULT_INTERNAL_NETWORKS = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
)


def parse_utc(value: Any) -> datetime:
    """Return a timezone-aware UTC datetime or raise ValueError."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, bool) or value is None:
        raise ValueError("A timestamp is required.")
    elif isinstance(value, (int, float)):
        try:
            parsed = datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as error:
            raise ValueError("Invalid Unix timestamp.") from error
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        # Suricata writes +0000 without a colon.
        if len(text) >= 5 and text[-5] in "+-" and text[-3] != ":":
            text = text[:-2] + ":" + text[-2:]
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as error:
            raise ValueError("Invalid ISO 8601 timestamp.") from error
    else:
        raise ValueError("Invalid timestamp.")

    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include a timezone.")

    return parsed.astimezone(timezone.utc)


def is_internal_address(
    address: str | None,
    networks: tuple[str, ...] = DEFAULT_INTERNAL_NETWORKS,
) -> bool | None:
    """True/False for a valid address, None when it cannot be determined."""
    if not address:
        return None
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    return any(ip in ipaddress.ip_network(net) for net in networks)


@dataclass(frozen=True)
class CanonicalEvent:
    event_id: str
    timestamp: datetime
    source: str                      # "suricata" | "zeek" | other sensor name
    event_type: str                  # alert | flow | network_connection | dns | ...
    source_ip: str
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    bytes_out: int | None = None     # bytes sent by source_ip (observed)
    bytes_in: int | None = None
    severity: int | None = None      # sensor severity, 1 = highest (observed)
    signature: str | None = None
    signature_id: int | None = None
    category: str | None = None
    raw_event_reference: str | None = None
    scenario_id: str | None = None
    run_id: str | None = None

    def __post_init__(self) -> None:
        if not self.event_id:
            raise ValueError("event_id is required.")
        if not self.source_ip:
            raise ValueError("source_ip is required.")
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware.")
        for name in ("source_port", "destination_port"):
            port = getattr(self, name)
            if port is not None and (
                isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
            ):
                raise ValueError(f"{name} must be between 1 and 65535.")
        for name in ("bytes_out", "bytes_in"):
            size = getattr(self, name)
            if size is not None and (isinstance(size, bool) or not isinstance(size, int) or size < 0):
                raise ValueError(f"{name} must be a non-negative integer.")

    @property
    def is_outbound(self) -> bool | None:
        """Internal source talking to an external destination."""
        src = is_internal_address(self.source_ip)
        dst = is_internal_address(self.destination_ip)
        if src is None or dst is None:
            return None
        return src and not dst


def _count(value: Any) -> int | None:
    """A non-negative integer, or None when the sensor did not report one."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def event_from_stored_telemetry(event_id: str, telemetry: dict[str, Any]) -> CanonicalEvent:
    """Build a canonical event from the telemetry JSON the prototype already
    persists in ``alerts.telemetry_json`` (NetworkTelemetryEvent)."""
    metadata = telemetry.get("lab_metadata") or {}
    port = telemetry.get("destination_port")
    return CanonicalEvent(
        event_id=event_id,
        timestamp=parse_utc(telemetry.get("timestamp")),
        source=str(telemetry.get("source") or "unknown"),
        event_type=str(telemetry.get("event_type") or "unknown"),
        source_ip=telemetry.get("source_ip") or "",
        destination_ip=telemetry.get("destination_ip") or None,
        destination_port=port if isinstance(port, int) and not isinstance(port, bool) else None,
        protocol=(telemetry.get("protocol") or None),
        bytes_out=_count(telemetry.get("bytes_out")),
        bytes_in=_count(telemetry.get("bytes_in")),
        signature_id=_count(telemetry.get("signature_id")),
        severity=telemetry.get("severity") if telemetry.get("event_type") == "alert" else None,
        signature=telemetry.get("signature") if telemetry.get("event_type") == "alert" else None,
        category=telemetry.get("category"),
        scenario_id=metadata.get("scenario") if isinstance(metadata, dict) else None,
        run_id=metadata.get("run_id") if isinstance(metadata, dict) else None,
    )
