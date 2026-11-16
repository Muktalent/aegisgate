"""Approved-activity allowlist: known benign jobs that look like attacks.

A backup job that contacts many file servers looks like a host sweep, and an
off-site backup looks like exfiltration. An analyst can record such activity
as approved. An entry is deliberately narrow and conservative:

* it names one source, the exact destinations (addresses or CIDR ranges), the
  optional destination ports and the detection categories it covers;
* a detection is suppressed only when **every** supporting event of that
  detection is covered by the entry. A scan that goes one address beyond the
  approved servers is still reported in full;
* suppression is never silent: suppressed detections are returned with the
  entry that suppressed them, stored with the analysis run and audited;
* IDS signature alerts (``ids_alert``) can never be allowlisted.

Limitation: an attacker who controls an approved host and stays inside the
approved destinations and ports is not detected by the covered rules. Entries
should therefore stay small and be reviewed.
"""
from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

from .detection import Detection
from .events import CanonicalEvent

ALLOWLIST_VERSION = "allowlist-1.0"
ALLOWABLE_CATEGORIES = ("port_scan", "destination_scan", "suspicious_outbound", "potential_exfiltration")


def _network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(value.strip(), strict=False)


@dataclass(frozen=True)
class AllowEntry:
    entry_id: str
    source_ip: str
    destinations: tuple[str, ...]
    categories: tuple[str, ...]
    reason: str
    ports: tuple[int, ...] = ()
    networks: tuple[Any, ...] = field(default=(), compare=False, repr=False)

    def __post_init__(self) -> None:
        ipaddress.ip_address(self.source_ip)                  # raises ValueError
        if not self.destinations:
            raise ValueError("At least one destination address or range is required.")
        if not self.categories:
            raise ValueError("At least one detection category is required.")
        unknown = set(self.categories) - set(ALLOWABLE_CATEGORIES)
        if unknown:
            raise ValueError(f"These categories cannot be allowlisted: {', '.join(sorted(unknown))}.")
        if not self.reason.strip():
            raise ValueError("A reason is required.")
        for port in self.ports:
            if not 0 < port < 65536:
                raise ValueError(f"Invalid port {port}.")
        networks = tuple(_network(d) for d in self.destinations)
        for network in networks:
            if network.num_addresses > 256:
                raise ValueError(f"Range {network} is too wide; at most 256 addresses (/24) per range.")
        object.__setattr__(self, "networks", networks)

    def covers(self, event: CanonicalEvent) -> bool:
        if event.source_ip != self.source_ip or not event.destination_ip:
            return False
        if self.ports and event.destination_port not in self.ports:
            return False
        try:
            address = ipaddress.ip_address(event.destination_ip)
        except ValueError:
            return False
        return any(address in network for network in self.networks)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("networks")
        data["destinations"] = list(self.destinations)
        data["categories"] = list(self.categories)
        data["ports"] = list(self.ports)
        return data


@dataclass(frozen=True)
class Suppression:
    detection: Detection
    entry_id: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"detection": self.detection.to_dict(), "entry_id": self.entry_id, "reason": self.reason}


def apply_allowlist(detections: Iterable[Detection], events: Iterable[CanonicalEvent],
                    entries: Iterable[AllowEntry]) -> tuple[list[Detection], list[Suppression]]:
    """Split detections into (kept, suppressed)."""
    entries = list(entries)
    detections = list(detections)
    if not entries:
        return detections, []
    by_id = {event.event_id: event for event in events}
    kept: list[Detection] = []
    suppressed: list[Suppression] = []
    for detection in detections:
        match = None
        if detection.category in ALLOWABLE_CATEGORIES:
            support = [by_id.get(event_id) for event_id in detection.supporting_events]
            if support and all(e is not None for e in support):
                match = next((entry for entry in entries
                              if entry.source_ip == detection.source_ip
                              and detection.category in entry.categories
                              and all(entry.covers(e) for e in support)), None)
        if match is None:
            kept.append(detection)
        else:
            suppressed.append(Suppression(detection, match.entry_id, match.reason))
    return kept, suppressed


def events_outside(events: Iterable[CanonicalEvent], entries: Iterable[AllowEntry]) -> list[CanonicalEvent]:
    """Events not covered by any entry (used by the anomaly-only baseline approach)."""
    entries = list(entries)
    return [event for event in events if not any(entry.covers(event) for entry in entries)]
