"""Event correlation (AG-08): group related detections into one finding.

Detections are related when they concern the same source address and are
separated by no more than the correlation window. Grouping preserves every
contributing detection and never asserts malicious intent.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable

from .detection import Detection, stable_id

CORRELATION_VERSION = "correlation-1.0"

# Ordered: the first pattern whose categories are all present names the group.
PATTERNS: tuple[tuple[str, frozenset[str], str], ...] = (
    ("potential_data_exfiltration", frozenset({"potential_exfiltration", "suspicious_outbound"}),
     "Large outbound volume together with repeated external connections."),
    ("potential_data_exfiltration", frozenset({"potential_exfiltration", "ids_alert"}),
     "Large outbound volume together with an IDS alert for the same source."),
    ("potential_network_reconnaissance", frozenset({"port_scan", "destination_scan"}),
     "Port diversity and destination diversity were both raised for the same source."),
    ("potential_network_reconnaissance", frozenset({"port_scan", "ids_alert"}),
     "Port diversity together with an IDS alert for the same source."),
    ("potential_network_reconnaissance", frozenset({"destination_scan", "ids_alert"}),
     "Destination diversity together with an IDS alert for the same source."),
    ("potential_command_and_control", frozenset({"suspicious_outbound", "ids_alert"}),
     "Regular external connections together with an IDS alert for the same source."),
)


@dataclass(frozen=True)
class CorrelationGroup:
    group_id: str
    finding: str
    source_ip: str
    window_start: datetime
    window_end: datetime
    detections: tuple[Detection, ...]
    categories: tuple[str, ...]
    explanation: str

    @property
    def is_correlated(self) -> bool:
        return len(self.categories) > 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id, "finding": self.finding, "source_ip": self.source_ip,
            "window_start": self.window_start.isoformat(), "window_end": self.window_end.isoformat(),
            "categories": list(self.categories), "is_correlated": self.is_correlated,
            "detection_ids": [d.detection_id for d in self.detections],
            "explanation": self.explanation, "correlation_version": CORRELATION_VERSION,
        }


def _name(categories: set[str]) -> tuple[str, str]:
    for finding, required, reason in PATTERNS:
        if required <= categories:
            return finding, reason
    if len(categories) == 1:
        return next(iter(categories)), "Single detection; no related finding in the correlation window."
    return "multiple_related_indicators", "Several different indicators were raised for the same source."


def correlate(detections: Iterable[Detection], window_seconds: int = 600) -> list[CorrelationGroup]:
    if window_seconds < 1:
        raise ValueError("window_seconds must be positive.")
    gap = timedelta(seconds=window_seconds)
    by_source: dict[str, list[Detection]] = {}
    for detection in {d.detection_id: d for d in detections}.values():   # drop exact duplicates
        by_source.setdefault(detection.source_ip, []).append(detection)

    groups: list[CorrelationGroup] = []
    for source_ip, items in sorted(by_source.items()):
        items.sort(key=lambda d: (d.window_start, d.detection_id))
        cluster: list[Detection] = []
        cluster_end: datetime | None = None
        for detection in items + [None]:
            if detection is not None and (cluster_end is None or detection.window_start - cluster_end <= gap):
                cluster.append(detection)
                cluster_end = max(cluster_end or detection.window_end, detection.window_end)
                continue
            if cluster:
                categories = {d.category for d in cluster}
                finding, reason = _name(categories)
                signals = "; ".join(f"{d.rule_id} {d.category} ({d.severity}, confidence {d.confidence})"
                                    for d in cluster)
                groups.append(CorrelationGroup(
                    group_id=stable_id("grp", source_ip, *sorted(d.detection_id for d in cluster)),
                    finding=finding, source_ip=source_ip,
                    window_start=min(d.window_start for d in cluster), window_end=cluster_end,
                    detections=tuple(cluster), categories=tuple(sorted(categories)),
                    explanation=(f"{reason} Contributing signals: {signals}. "
                                 "Correlation shows that indicators coincide; it does not establish intent."),
                ))
            cluster = [detection] if detection is not None else []
            cluster_end = detection.window_end if detection is not None else None
    return sorted(groups, key=lambda g: (g.window_start, g.group_id))
