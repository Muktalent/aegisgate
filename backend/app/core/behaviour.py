"""Behaviour analytics with an explainable statistical baseline (AG-07).

Metrics are computed per source address in fixed time buckets. The baseline
of a metric is the median of its historical buckets, and spread is the
median absolute deviation (MAD). No machine-learning model is involved.
"""
from __future__ import annotations

import statistics
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from .events import CanonicalEvent

METRICS = ("destination_diversity", "port_diversity", "connection_count",
           "outbound_bytes", "outbound_connections", "inbound_or_internal_connections")
MAD_SCALE = 1.4826            # makes MAD comparable to a standard deviation
INSUFFICIENT = "insufficient_baseline_data"


@dataclass(frozen=True)
class BucketMetrics:
    source_ip: str
    bucket_start: datetime
    bucket_seconds: int
    destination_diversity: int
    port_diversity: int
    connection_count: int
    outbound_bytes: int | None        # None when no event reported byte counts
    outbound_connections: int
    inbound_or_internal_connections: int
    undetermined_direction: int

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["bucket_start"] = self.bucket_start.isoformat()
        return data


def bucket_metrics(events: Iterable[CanonicalEvent], bucket_seconds: int = 300) -> list[BucketMetrics]:
    if bucket_seconds < 1:
        raise ValueError("bucket_seconds must be positive.")
    groups: dict[tuple[str, int], list[CanonicalEvent]] = {}
    for event in events:
        index = int(event.timestamp.timestamp()) // bucket_seconds
        groups.setdefault((event.source_ip, index), []).append(event)

    result = []
    for (source_ip, index), items in sorted(groups.items()):
        sizes = [e.bytes_out for e in items if e.bytes_out is not None and e.is_outbound]
        directions = [e.is_outbound for e in items]
        result.append(BucketMetrics(
            source_ip=source_ip,
            bucket_start=datetime.fromtimestamp(index * bucket_seconds, tz=timezone.utc),
            bucket_seconds=bucket_seconds,
            destination_diversity=len({e.destination_ip for e in items if e.destination_ip}),
            port_diversity=len({e.destination_port for e in items if e.destination_port}),
            connection_count=len(items),
            outbound_bytes=sum(sizes) if sizes else None,
            outbound_connections=sum(1 for d in directions if d is True),
            inbound_or_internal_connections=sum(1 for d in directions if d is False),
            undetermined_direction=sum(1 for d in directions if d is None),
        ))
    return result


@dataclass(frozen=True)
class BaselineComparison:
    source_ip: str
    metric: str
    status: str                 # within_baseline | above_baseline | insufficient_baseline_data
    observed: float | None
    baseline_median: float | None
    baseline_mad: float | None
    deviation: float | None     # robust z-score
    sample_count: int
    min_samples: int
    deviation_threshold: float
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compare_to_baseline(
    source_ip: str,
    metric: str,
    observed: float | None,
    history: list[float],
    *,
    min_samples: int = 8,
    deviation_threshold: float = 3.5,
) -> BaselineComparison:
    """Compare one observation with the asset's own history.

    Cold start: with fewer than ``min_samples`` historical buckets the result
    is "insufficient_baseline_data" and no normal range is assumed.
    When MAD is zero (a perfectly flat history) the spread falls back to 10%
    of the median, with a floor of 1, so a flat history cannot produce an
    infinite deviation.
    """
    if metric not in METRICS:
        raise ValueError(f"Unknown metric: {metric}")
    if min_samples < 2:
        raise ValueError("min_samples must be at least 2.")

    common = dict(source_ip=source_ip, metric=metric, observed=observed, sample_count=len(history),
                  min_samples=min_samples, deviation_threshold=deviation_threshold)
    if observed is None or len(history) < min_samples:
        reason = ("no observation for this metric" if observed is None
                  else f"{len(history)} historical samples, {min_samples} required")
        return BaselineComparison(status=INSUFFICIENT, baseline_median=None, baseline_mad=None,
                                  deviation=None, explanation=f"Insufficient baseline data: {reason}.",
                                  **common)

    median = statistics.median(history)
    mad = statistics.median(abs(value - median) for value in history)
    spread = mad * MAD_SCALE if mad > 0 else max(1.0, 0.1 * abs(median))
    deviation = round((observed - median) / spread, 2)
    above = deviation >= deviation_threshold
    return BaselineComparison(
        status="above_baseline" if above else "within_baseline",
        baseline_median=round(median, 2), baseline_mad=round(mad, 2), deviation=deviation,
        explanation=(f"Observed {observed:g} against a median of {median:g} over {len(history)} samples; "
                     f"robust deviation {deviation:g} (threshold {deviation_threshold:g})."),
        **common,
    )


def history_for(metrics: list[BucketMetrics], source_ip: str, metric: str,
                before: datetime) -> list[float]:
    """Historical values of one metric for one source, strictly before a time."""
    values = []
    for bucket in metrics:
        if bucket.source_ip != source_ip:
            continue
        if bucket.bucket_start + timedelta(seconds=bucket.bucket_seconds) > before:
            continue
        value = getattr(bucket, metric)
        if value is not None:
            values.append(float(value))
    return values


def typical_outbound_bytes(metrics: list[BucketMetrics], before: datetime,
                           min_samples: int = 8) -> dict[str, float]:
    """Median outbound bytes per bucket for each source with enough history."""
    result: dict[str, float] = {}
    for source_ip in sorted({m.source_ip for m in metrics}):
        values = history_for(metrics, source_ip, "outbound_bytes", before)
        if len(values) >= min_samples:
            result[source_ip] = statistics.median(values)
    return result
