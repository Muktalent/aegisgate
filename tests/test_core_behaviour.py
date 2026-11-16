import pytest

from core_helpers import T0, ev, office_traffic, port_scan
from app.core.behaviour import (INSUFFICIENT, bucket_metrics, compare_to_baseline,
                                history_for, typical_outbound_bytes)


def test_bucket_metrics_are_computed_from_events():
    events = port_scan(20) + [ev(30, dst="198.51.100.9", port=443, bytes_out=5000)]
    (bucket,) = bucket_metrics(events)
    assert bucket.port_diversity == 21 and bucket.destination_diversity == 2
    assert bucket.connection_count == 21 and bucket.outbound_bytes == 5000
    assert bucket.outbound_connections == 1 and bucket.inbound_or_internal_connections == 20


def test_outbound_bytes_unknown_when_no_sizes_reported():
    (bucket,) = bucket_metrics([ev(0, dst="198.51.100.9")])
    assert bucket.outbound_bytes is None


def test_cold_start_reports_insufficient_baseline():
    result = compare_to_baseline("10.10.10.25", "port_diversity", 20, [2, 3, 2])
    assert result.status == INSUFFICIENT and result.deviation is None and result.baseline_median is None
    assert "Insufficient baseline data" in result.explanation


def test_missing_observation_reports_insufficient():
    assert compare_to_baseline("x", "outbound_bytes", None, [1] * 20).status == INSUFFICIENT


def test_above_and_within_baseline():
    history = [2, 3, 2, 4, 3, 2, 3, 3, 2, 4]
    high = compare_to_baseline("x", "port_diversity", 20, history)
    normal = compare_to_baseline("x", "port_diversity", 4, history)
    assert high.status == "above_baseline" and high.deviation >= 3.5
    assert normal.status == "within_baseline"


def test_flat_history_does_not_divide_by_zero():
    result = compare_to_baseline("x", "connection_count", 30, [10] * 12)
    assert result.baseline_mad == 0 and result.status == "above_baseline" and result.deviation == 20.0
    assert compare_to_baseline("x", "connection_count", 10, [10] * 12).status == "within_baseline"


def test_baseline_is_reproducible():
    history = [5, 7, 6, 9, 5, 6, 8, 7]
    assert compare_to_baseline("x", "port_diversity", 12, history) == \
        compare_to_baseline("x", "port_diversity", 12, list(history))


def test_invalid_parameters():
    with pytest.raises(ValueError):
        compare_to_baseline("x", "not_a_metric", 1, [1] * 10)
    with pytest.raises(ValueError):
        compare_to_baseline("x", "port_diversity", 1, [1] * 10, min_samples=1)
    with pytest.raises(ValueError):
        bucket_metrics([], bucket_seconds=0)


def test_history_excludes_current_and_future_buckets_and_other_sources():
    metrics = bucket_metrics(office_traffic() + office_traffic(src="10.10.10.50") + port_scan(20))
    values = history_for(metrics, "10.10.10.25", "port_diversity", T0)
    assert len(values) == 8 and max(values) <= 2


def test_typical_outbound_bytes_needs_enough_history():
    metrics = bucket_metrics(office_traffic())
    assert "10.10.10.25" in typical_outbound_bytes(metrics, T0)
    assert typical_outbound_bytes(metrics, T0, min_samples=50) == {}
