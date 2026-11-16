"""Structured detection rules (AG-06).

Each rule has an identifier, version, configurable thresholds and an
observation window, and returns detections that list the supporting events.
No rule inspects free text for keywords. A detection is an indicator that
needs review; it is never proof of an attack.
"""
from __future__ import annotations

import hashlib
import statistics
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterable

from .events import CanonicalEvent, is_internal_address

SEVERITIES = ("low", "medium", "high", "critical")
FLOW_EVENT_TYPES = frozenset({"flow", "network_connection", "connection"})


@dataclass(frozen=True)
class Detection:
    detection_id: str
    rule_id: str
    rule_version: str
    category: str
    source_ip: str
    severity: str
    confidence: float
    window_start: datetime
    window_end: datetime
    supporting_events: tuple[str, ...]
    observations: dict[str, Any]
    explanation: str
    limitations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["window_start"] = self.window_start.isoformat()
        data["window_end"] = self.window_end.isoformat()
        data["supporting_events"] = list(self.supporting_events)
        data["limitations"] = list(self.limitations)
        return data


def stable_id(prefix: str, *parts: str) -> str:
    """Deterministic identifier, so re-importing the same evidence yields the
    same detection instead of a duplicate."""
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]
    return f"{prefix}-{digest}"


def _scaled_confidence(observed: float, threshold: float, floor: float, ceiling: float) -> float:
    """Confidence grows linearly from ``floor`` at the threshold to
    ``ceiling`` at twice the threshold, and is capped there."""
    if threshold <= 0:
        return floor
    excess = max(0.0, min(1.0, (observed - threshold) / threshold))
    return round(floor + (ceiling - floor) * excess, 2)


def _by_source(events: Iterable[CanonicalEvent]) -> dict[str, list[CanonicalEvent]]:
    grouped: dict[str, list[CanonicalEvent]] = {}
    for event in events:
        grouped.setdefault(event.source_ip, []).append(event)
    for items in grouped.values():
        items.sort(key=lambda e: (e.timestamp, e.event_id))   # out-of-order input is fine
    return grouped


@dataclass
class DetectionRule:
    rule_id: str = ""
    version: str = "1.0"
    category: str = ""
    description: str = ""
    input_requirements: str = ""
    window_seconds: int = 60

    def evaluate(self, events: list[CanonicalEvent]) -> list[Detection]:  # pragma: no cover
        raise NotImplementedError

    def describe(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items()}

    def _make(self, source_ip: str, window: list[CanonicalEvent], severity: str,
              confidence: float, observations: dict[str, Any], explanation: str,
              limitations: tuple[str, ...],
              evidence: list[CanonicalEvent] | None = None) -> Detection:
        """``evidence`` narrows the supporting events to those that actually
        establish the finding; the time window still spans ``window``."""
        ids = tuple(sorted(e.event_id for e in (evidence if evidence is not None else window)))
        return Detection(
            detection_id=stable_id("det", self.rule_id, self.version, source_ip, *ids),
            rule_id=self.rule_id, rule_version=self.version, category=self.category,
            source_ip=source_ip, severity=severity, confidence=confidence,
            window_start=window[0].timestamp, window_end=window[-1].timestamp,
            supporting_events=ids, observations=observations,
            explanation=explanation, limitations=limitations,
        )

    def _windows(self, items: list[CanonicalEvent]):
        """Yield maximal non-overlapping windows of at most window_seconds,
        each starting at the first event not yet consumed."""
        span = timedelta(seconds=self.window_seconds)
        start = 0
        while start < len(items):
            end = start
            while end + 1 < len(items) and items[end + 1].timestamp - items[start].timestamp <= span:
                end += 1
            consumed = yield items[start:end + 1]
            start = end + 1 if consumed else start + 1


@dataclass
class _DiversityRule(DetectionRule):
    threshold: int = 15
    high_multiplier: int = 3      # severity becomes high at threshold * multiplier

    def _key(self, event: CanonicalEvent):  # pragma: no cover
        raise NotImplementedError

    def _text(self, count: int) -> tuple[str, dict[str, Any], tuple[str, ...]]:  # pragma: no cover
        raise NotImplementedError

    def evaluate(self, events: list[CanonicalEvent]) -> list[Detection]:
        found: list[Detection] = []
        for source_ip, items in _by_source(events).items():
            usable = [e for e in items if self._key(e) is not None]
            windows = self._windows(usable)
            try:
                window = next(windows)
                while True:
                    distinct = {self._key(e) for e in window}
                    hit = len(distinct) >= self.threshold
                    if hit:
                        severity = "high" if len(distinct) >= self.threshold * self.high_multiplier else "medium"
                        explanation, observations, limits = self._text(len(distinct))
                        observations["distinct_values"] = sorted(distinct, key=str)[:100]
                        observations["events_in_window"] = len(window)
                        # Evidence = the first event for each distinct value, i.e. the
                        # events that raised the diversity. Repeats add nothing.
                        first_seen: dict[Any, CanonicalEvent] = {}
                        for event in window:
                            first_seen.setdefault(self._key(event), event)
                        found.append(self._make(
                            source_ip, window, severity,
                            _scaled_confidence(len(distinct), self.threshold, 0.6, 0.9),
                            observations, explanation, limits,
                            evidence=list(first_seen.values()),
                        ))
                    window = windows.send(hit)
            except StopIteration:
                pass
        return found


@dataclass
class PortScanRule(_DiversityRule):
    rule_id: str = "DET-001"
    category: str = "port_scan"
    description: str = "High destination-port diversity from one source inside the observation window."
    input_requirements: str = "Events with source_ip, destination_ip and destination_port."
    threshold: int = 15

    def _key(self, event):
        if event.destination_ip is None or event.destination_port is None:
            return None
        return event.destination_port

    def _text(self, count):
        return (
            f"{count} distinct destination ports were contacted within {self.window_seconds} seconds "
            f"(threshold {self.threshold}).",
            {"distinct_port_count": count, "threshold": self.threshold, "window_seconds": self.window_seconds},
            ("Port numbers are counted across all destinations.",
             "TCP and UDP ports are not distinguished.",
             "Vulnerability scanners and some management tools behave the same way."),
        )


@dataclass
class DestinationScanRule(_DiversityRule):
    rule_id: str = "DET-002"
    category: str = "destination_scan"
    description: str = "One source contacts an unusually large number of different hosts inside the window."
    input_requirements: str = "Events with source_ip and destination_ip."
    threshold: int = 10

    def _key(self, event):
        return event.destination_ip

    def _text(self, count):
        return (
            f"{count} distinct destination hosts were contacted within {self.window_seconds} seconds "
            f"(threshold {self.threshold}).",
            {"distinct_destination_count": count, "threshold": self.threshold,
             "window_seconds": self.window_seconds},
            ("Backup, monitoring and software-distribution servers legitimately contact many hosts.",),
        )


@dataclass
class SuspiciousOutboundRule(DetectionRule):
    """Repeated, evenly spaced connections to one external destination."""
    rule_id: str = "DET-003"
    category: str = "suspicious_outbound"
    description: str = "Repeated connections to one external destination at near-regular intervals."
    input_requirements: str = "Flow or connection events from an internal source to an external destination."
    window_seconds: int = 600
    min_connections: int = 8
    max_interval_variation: float = 0.2   # coefficient of variation of the gaps

    def evaluate(self, events: list[CanonicalEvent]) -> list[Detection]:
        found: list[Detection] = []
        for source_ip, items in _by_source(events).items():
            per_destination: dict[str, list[CanonicalEvent]] = {}
            for event in items:
                if event.event_type in FLOW_EVENT_TYPES and event.is_outbound:
                    per_destination.setdefault(event.destination_ip, []).append(event)
            for destination, flows in sorted(per_destination.items()):
                windows = self._windows(flows)
                try:
                    window = next(windows)
                    while True:
                        hit = False
                        if len(window) >= self.min_connections:
                            gaps = [(b.timestamp - a.timestamp).total_seconds()
                                    for a, b in zip(window, window[1:])]
                            mean_gap = statistics.fmean(gaps)
                            variation = statistics.pstdev(gaps) / mean_gap if mean_gap > 0 else None
                            hit = variation is not None and variation <= self.max_interval_variation
                            if hit:
                                found.append(self._make(
                                    source_ip, window, "medium",
                                    _scaled_confidence(len(window), self.min_connections, 0.5, 0.8),
                                    {"destination_ip": destination, "connection_count": len(window),
                                     "mean_interval_seconds": round(mean_gap, 2),
                                     "interval_variation": round(variation, 3),
                                     "window_seconds": self.window_seconds},
                                    f"{len(window)} connections to external host {destination} at intervals of "
                                    f"about {round(mean_gap)} seconds with little variation.",
                                    ("Software updaters, telemetry and time synchronisation also connect at regular intervals.",
                                     "The destination is judged external only by address range."),
                                ))
                        # Each window is judged once as a whole. Sliding past a miss would
                        # re-test ever shorter tail fragments, which pass by chance.
                        window = windows.send(True)
                except StopIteration:
                    pass
        return found


@dataclass
class PotentialExfiltrationRule(DetectionRule):
    rule_id: str = "DET-004"
    category: str = "potential_exfiltration"
    description: str = "Outbound byte volume to external destinations above a defined level."
    input_requirements: str = "Flow or connection events with bytes_out."
    window_seconds: int = 300
    absolute_threshold_bytes: int = 50 * 1024 * 1024
    baseline_multiplier: float = 5.0

    def evaluate(self, events: list[CanonicalEvent],
                 baseline_bytes: dict[str, float] | None = None) -> list[Detection]:
        """``baseline_bytes`` maps source_ip to its typical outbound bytes per
        window (see behaviour.py). Without it only the absolute threshold applies."""
        found: list[Detection] = []
        for source_ip, items in _by_source(events).items():
            flows = [e for e in items
                     if e.event_type in FLOW_EVENT_TYPES and e.is_outbound and e.bytes_out is not None]
            baseline = (baseline_bytes or {}).get(source_ip)
            threshold = float(self.absolute_threshold_bytes)
            basis = "absolute threshold; insufficient baseline data"
            if baseline is not None and baseline > 0:
                threshold = min(threshold, baseline * self.baseline_multiplier)
                basis = f"{self.baseline_multiplier:g} times the asset baseline or the absolute threshold"
            windows = self._windows(flows)
            try:
                window = next(windows)
                while True:
                    total = sum(e.bytes_out for e in window)
                    hit = total >= threshold
                    if hit:
                        found.append(self._make(
                            source_ip, window, "high" if total >= threshold * 5 else "medium",
                            _scaled_confidence(total, threshold, 0.5, 0.8),
                            {"outbound_bytes": total, "threshold_bytes": int(threshold),
                             "threshold_basis": basis, "baseline_bytes": baseline,
                             "destinations": sorted({e.destination_ip for e in window}),
                             "window_seconds": self.window_seconds},
                            f"{total} bytes were sent to external destinations within {self.window_seconds} "
                            f"seconds (threshold {int(threshold)} bytes, {basis}).",
                            ("This is an indicator of possible exfiltration, not proof of data theft.",
                             "Cloud backup, uploads and video calls also produce large outbound volumes.",
                             "Payload content is not inspected."),
                        ))
                    window = windows.send(hit)
            except StopIteration:
                pass
        return found


@dataclass
class IdsAlertRule(DetectionRule):
    rule_id: str = "DET-005"
    category: str = "ids_alert"
    description: str = "Suricata signature alerts grouped by source and signature."
    input_requirements: str = "Suricata alert events with a signature and severity."
    window_seconds: int = 300
    base_confidence: float = 0.6
    severity_map: dict[int, str] = field(default_factory=lambda: {1: "high", 2: "medium", 3: "low"})

    def evaluate(self, events: list[CanonicalEvent]) -> list[Detection]:
        found: list[Detection] = []
        for source_ip, items in _by_source(events).items():
            per_signature: dict[str, list[CanonicalEvent]] = {}
            for event in items:
                if event.source == "suricata" and event.event_type == "alert":
                    key = str(event.signature_id) if event.signature_id is not None else (event.signature or "")
                    if key:
                        per_signature.setdefault(key, []).append(event)
            for key, alerts in sorted(per_signature.items()):
                windows = self._windows(alerts)
                try:
                    window = next(windows)
                    while True:
                        levels = [e.severity for e in window if e.severity is not None]
                        severity = self.severity_map.get(min(levels), "low") if levels else "low"
                        found.append(self._make(
                            source_ip, window, severity, self.base_confidence,
                            {"signature": window[0].signature, "signature_id": window[0].signature_id,
                             "sensor_category": window[0].category, "alert_count": len(window),
                             "sensor_severity": min(levels) if levels else None},
                            f"Suricata raised {len(window)} alert(s) for signature "
                            f"'{window[0].signature or key}'.",
                            ("A signature match shows that traffic resembled a known pattern.",
                             "It does not show that an attack succeeded.",
                             "Signature quality varies; some rules are noisy."),
                        ))
                        window = windows.send(True)
                except StopIteration:
                    pass
        return found


class DetectionEngine:
    def __init__(self, rules: list[DetectionRule] | None = None) -> None:
        self.rules = rules if rules is not None else [
            PortScanRule(), DestinationScanRule(), SuspiciousOutboundRule(),
            PotentialExfiltrationRule(), IdsAlertRule(),
        ]

    @property
    def ruleset_version(self) -> str:
        return "+".join(f"{r.rule_id}@{r.version}" for r in self.rules)

    def run(self, events: Iterable[CanonicalEvent],
            baseline_bytes: dict[str, float] | None = None) -> list[Detection]:
        # The same event submitted twice must not count twice.
        batch = list({event.event_id: event for event in events}.values())
        detections: dict[str, Detection] = {}
        for rule in self.rules:
            if isinstance(rule, PotentialExfiltrationRule):
                results = rule.evaluate(batch, baseline_bytes)
            else:
                results = rule.evaluate(batch)
            for detection in results:
                detections[detection.detection_id] = detection   # same evidence, same id
        return sorted(detections.values(), key=lambda d: (d.window_start, d.rule_id, d.detection_id))
