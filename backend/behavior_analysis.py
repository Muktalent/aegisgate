from datetime import datetime, timedelta
from typing import Any

from telemetry_adapters import parse_timestamp


def analyze_destination_diversity(
    events: list[dict[str, Any]],
    *,
    source_ip: str,
    window_end: datetime,
    window_minutes: int = 5,
    destination_threshold: int = 10,
) -> dict[str, Any]:
    if window_end.tzinfo is None:
        raise ValueError("window_end must include a timezone.")

    if window_minutes < 1:
        raise ValueError("window_minutes must be positive.")

    if destination_threshold < 2:
        raise ValueError("destination_threshold must be at least 2.")

    end = parse_timestamp(window_end.isoformat())
    start = end - timedelta(minutes=window_minutes)

    destinations: set[str] = set()
    evidence_ids: set[str] = set()
    matching_records = 0
    skipped_invalid_timestamps = 0

    for event in events:
        telemetry = event.get("telemetry", {})

        if telemetry.get("source_ip") != source_ip:
            continue

        try:
            timestamp = parse_timestamp(telemetry.get("timestamp"))
        except ValueError:
            skipped_invalid_timestamps += 1
            continue

        if not start <= timestamp <= end:
            continue

        destination = telemetry.get("destination_ip")

        if not isinstance(destination, str) or not destination:
            continue

        destinations.add(destination)
        matching_records += 1

        event_id = event.get("event_id")
        if isinstance(event_id, str) and event_id:
            evidence_ids.add(event_id)

    triggered = len(destinations) >= destination_threshold

    return {
        "analysis_type": "destination_diversity",
        "source_ip": source_ip,
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "destination_threshold": destination_threshold,
        "unique_destination_count": len(destinations),
        "observed_destinations": sorted(destinations),
        "matching_record_count": matching_records,
        "evidence_event_ids": sorted(evidence_ids),
        "skipped_invalid_timestamps": skipped_invalid_timestamps,
        "triggered": triggered,
        "interpretation": (
            "Destination diversity reached the configured threshold. "
            "Review the supporting events and asset context."
            if triggered
            else
            "Destination diversity did not reach the configured threshold."
        ),
        "limitations": [
            "This counts observed destinations, not connections.",
            "The threshold is a configured heuristic, not a learned baseline.",
            "A triggered finding does not confirm malicious activity.",
            "Results depend on the available telemetry.",
        ],
    }

def analyze_port_diversity(
    events: list[dict[str, Any]],
    *,
    source_ip: str,
    window_end: datetime,
    window_minutes: int = 5,
    port_threshold: int = 10,
    destination_ip: str | None = None,
) -> dict[str, Any]:
    if window_end.tzinfo is None:
        raise ValueError("window_end must include a timezone.")

    if window_minutes < 1:
        raise ValueError("window_minutes must be positive.")

    if port_threshold < 2:
        raise ValueError("port_threshold must be at least 2.")

    end = parse_timestamp(window_end.isoformat())
    start = end - timedelta(minutes=window_minutes)

    ports: set[int] = set()
    ports_by_destination: dict[str, set[int]] = {}
    evidence_ids: set[str] = set()

    matching_records = 0
    skipped_invalid_timestamps = 0
    skipped_invalid_ports = 0

    for event in events:
        telemetry = event.get("telemetry", {})

        if telemetry.get("source_ip") != source_ip:
            continue

        destination = telemetry.get("destination_ip")

        if not isinstance(destination, str) or not destination:
            continue

        if destination_ip is not None and destination != destination_ip:
            continue

        try:
            timestamp = parse_timestamp(telemetry.get("timestamp"))
        except ValueError:
            skipped_invalid_timestamps += 1
            continue

        if not start <= timestamp <= end:
            continue

        port = telemetry.get("destination_port")

        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            skipped_invalid_ports += 1
            continue

        ports.add(port)
        ports_by_destination.setdefault(destination, set()).add(port)
        matching_records += 1

        event_id = event.get("event_id")
        if isinstance(event_id, str) and event_id:
            evidence_ids.add(event_id)

    triggered = len(ports) >= port_threshold

    return {
        "analysis_type": "port_diversity",
        "source_ip": source_ip,
        "destination_filter": destination_ip,
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "port_threshold": port_threshold,
        "unique_port_count": len(ports),
        "observed_ports": sorted(ports),
        "ports_by_destination": {
            destination: sorted(destination_ports)
            for destination, destination_ports in sorted(
                ports_by_destination.items()
            )
        },
        "matching_record_count": matching_records,
        "evidence_event_ids": sorted(evidence_ids),
        "skipped_invalid_timestamps": skipped_invalid_timestamps,
        "skipped_invalid_ports": skipped_invalid_ports,
        "triggered": triggered,
        "interpretation": (
            "Port diversity reached the configured threshold. "
            "Review the supporting events and destination context."
            if triggered
            else
            "Port diversity did not reach the configured threshold."
        ),
        "limitations": [
            "This counts observed destination port numbers, not connections.",
            "The same port number across destinations is counted once.",
            "TCP and UDP port numbers are not distinguished in this version.",
            "The threshold is a configured heuristic, not a learned baseline.",
            "A triggered finding does not confirm scanning or malicious activity.",
            "Results depend on the available telemetry.",
        ],
    }

def analyze_network_behavior(
    events: list[dict[str, Any]],
    *,
    source_ip: str,
    window_end: datetime,
    window_minutes: int = 5,
    destination_threshold: int = 10,
    port_threshold: int = 10,
) -> dict[str, Any]:
    destination_analysis = analyze_destination_diversity(
        events,
        source_ip=source_ip,
        window_end=window_end,
        window_minutes=window_minutes,
        destination_threshold=destination_threshold,
    )

    port_analysis = analyze_port_diversity(
        events,
        source_ip=source_ip,
        window_end=window_end,
        window_minutes=window_minutes,
        port_threshold=port_threshold,
    )

    destination_triggered = destination_analysis["triggered"]
    port_triggered = port_analysis["triggered"]

    patterns = {
        (False, False): (
            "neither_threshold_reached",
            "Neither diversity signal reached its configured threshold.",
        ),
        (True, False): (
            "destination_threshold_only",
            "Destination diversity reached its configured threshold; "
            "port diversity did not.",
        ),
        (False, True): (
            "port_threshold_only",
            "Port diversity reached its configured threshold; "
            "destination diversity did not.",
        ),
        (True, True): (
            "both_thresholds_reached",
            "Both diversity signals reached their configured thresholds.",
        ),
    }

    pattern, interpretation = patterns[
        (destination_triggered, port_triggered)
    ]

    destination_evidence = set(
        destination_analysis["evidence_event_ids"]
    )
    port_evidence = set(port_analysis["evidence_event_ids"])

    return {
        "analysis_type": "network_behavior_summary",
        "source_ip": source_ip,
        "window_start": destination_analysis["window_start"],
        "window_end": destination_analysis["window_end"],
        "window_minutes": window_minutes,
        "pattern": pattern,
        "triggered": destination_triggered or port_triggered,
        "interpretation": interpretation,
        "destination_analysis": destination_analysis,
        "port_analysis": port_analysis,
        "evidence_event_ids": sorted(
            destination_evidence | port_evidence
        ),
        "shared_evidence_event_ids": sorted(
            destination_evidence & port_evidence
        ),
        "destination_only_evidence_event_ids": sorted(
            destination_evidence - port_evidence
        ),
        "port_only_evidence_event_ids": sorted(
            port_evidence - destination_evidence
        ),
        "limitations": [
            "This summarizes two configured heuristics, not a learned baseline.",
            "The signals may accept different sets of records.",
            "Shared evidence means shared event IDs, not confirmed connections.",
            "Both thresholds being reached does not establish a scan pattern.",
            "A triggered summary does not confirm malicious activity.",
            "Neither threshold being reached does not establish safety.",
            "Records without valid ports do not contribute to port diversity.",
            "TCP and UDP port numbers are not distinguished in this version.",
            "Results depend on the available telemetry.",
        ],
    }