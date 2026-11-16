from datetime import UTC, datetime
from typing import Any

from telemetry_models import NetworkTelemetryEvent
import math

MALICIOUS_KEYWORDS = (
    "malware",
    "trojan",
    "c2",
    "command and control",
    "ransomware",
    "exploit",
    "phishing",
    "botnet",
    "suspicious",
)


def parse_timestamp(value: str | int | float | None) -> datetime:
    if value is None:
        raise ValueError("Telemetry timestamp is required.")

    if isinstance(value, bool):
        raise ValueError("Telemetry timestamp cannot be a boolean.")

    if isinstance(value, (int, float)):
        try:
            if not math.isfinite(value):
                raise ValueError("Non-finite timestamp.")

            return datetime.fromtimestamp(value, tz=UTC)
        except (ValueError, OverflowError, OSError) as error:
            raise ValueError(
                "Invalid Unix timestamp."
            ) from error

    if not isinstance(value, str) or not value.strip():
        raise ValueError("Invalid telemetry timestamp.")

    normalized = value.strip().replace("Z", "+00:00")

    try:
        timestamp = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ValueError(
            "Invalid ISO 8601 timestamp."
        ) from error

    if timestamp.tzinfo is None:
        raise ValueError(
            "Telemetry timestamp must include a timezone."
        )

    return timestamp.astimezone(UTC)


def is_malicious_text(*values: str | None) -> bool:
    text = " ".join(value or "" for value in values).lower()

    return any(keyword in text for keyword in MALICIOUS_KEYWORDS)


def observed_count(value: Any) -> int | None:
    """A non-negative integer reported by the sensor, otherwise None."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None

    return value


def normalize_suricata_event(raw_event: dict[str, Any]) -> NetworkTelemetryEvent:
    event_type = raw_event.get("event_type", "unknown")
    alert = raw_event.get("alert", {})

    signature = alert.get("signature")
    category = alert.get("category")
    severity = alert.get("severity", 3)

    return NetworkTelemetryEvent(
        source="suricata",
        event_type=event_type,
        timestamp=parse_timestamp(raw_event.get("timestamp")),
        source_ip=raw_event.get("src_ip", "0.0.0.0"),
        destination_ip=raw_event.get("dest_ip"),
        destination_port=raw_event.get("dest_port"),
        protocol=raw_event.get("proto"),
        severity=severity if isinstance(severity, int) else 3,
        signature=signature,
        category=category,
        indicator=raw_event.get("dns", {}).get("rrname"),
        is_malicious=is_malicious_text(signature, category),
        bytes_out=observed_count((raw_event.get("flow") or {}).get("bytes_toserver")),
        bytes_in=observed_count((raw_event.get("flow") or {}).get("bytes_toclient")),
        signature_id=observed_count(alert.get("signature_id")),
        lab_metadata=raw_event.get("aegisgate_lab"),
        raw_event=raw_event,
    )


def normalize_zeek_event(
    raw_event: dict[str, Any],
    log_type: str,
) -> NetworkTelemetryEvent:
    note = raw_event.get("note")
    message = raw_event.get("msg")
    query = raw_event.get("query")

    if log_type == "notice":
        signature = note or message or "Zeek notice"
        category = raw_event.get("sub")
        severity = 1 if is_malicious_text(signature, category) else 3
        source_ip = raw_event.get("src", "0.0.0.0")
        destination_ip = raw_event.get("dst")
    elif log_type == "dns":
        signature = "Zeek DNS observation"
        category = raw_event.get("qtype_name")
        severity = 2 if is_malicious_text(query) else 4
        source_ip = raw_event.get("id.orig_h", "0.0.0.0")
        destination_ip = raw_event.get("id.resp_h")
    else:
        signature = "Zeek network connection"
        category = raw_event.get("service")
        severity = 4
        source_ip = raw_event.get("id.orig_h", "0.0.0.0")
        destination_ip = raw_event.get("id.resp_h")

    return NetworkTelemetryEvent(
        source="zeek",
        event_type=log_type,
        timestamp=parse_timestamp(raw_event.get("ts")),
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=raw_event.get("id.resp_p"),
        protocol=raw_event.get("proto"),
        severity=severity,
        signature=signature,
        category=category,
        indicator=query,
        is_malicious=is_malicious_text(signature, category, query),
        bytes_out=observed_count(raw_event.get("orig_bytes")),
        bytes_in=observed_count(raw_event.get("resp_bytes")),
        lab_metadata=raw_event.get("aegisgate_lab"),
        raw_event=raw_event,
    )


def normalize_network_telemetry(raw_event: dict[str, Any]) -> NetworkTelemetryEvent:
    if "event_type" in raw_event and "src_ip" in raw_event:
        return normalize_suricata_event(raw_event)

    if "id.orig_h" in raw_event or "note" in raw_event:
        # Zeek's JSON writer names the log in "_path"; "conn" is the connection log.
        log_type = raw_event.get("_zeek_log_type") or raw_event.get("_path") or "connection"
        log_type = {"conn": "connection"}.get(log_type, log_type)
        return normalize_zeek_event(raw_event, log_type)

    raise ValueError("Unsupported telemetry format.")