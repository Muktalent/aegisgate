import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest


sys.path.append(
    str(Path(__file__).resolve().parents[1] / "backend")
)

from telemetry_adapters import parse_timestamp


def test_iso_timestamp_with_z():
    result = parse_timestamp("2026-10-12T20:00:00Z")

    assert result == datetime(2026, 10, 12, 20, tzinfo=UTC)


def test_timestamp_with_offset_is_converted_to_utc():
    result = parse_timestamp("2026-10-12T21:00:00+01:00")

    assert result == datetime(2026, 10, 12, 20, tzinfo=UTC)


def test_unix_timestamp():
    result = parse_timestamp(0)

    assert result == datetime(1970, 1, 1, tzinfo=UTC)


def test_fractional_unix_timestamp():
    result = parse_timestamp(0.5)

    assert result == datetime(
        1970, 1, 1, microsecond=500000, tzinfo=UTC
    )


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "not-a-timestamp",
        "2026-10-12T20:00:00",
        True,
        float("nan"),
        float("inf"),
        {},
    ],
)
def test_invalid_timestamp_is_rejected(value):
    with pytest.raises(ValueError):
        parse_timestamp(value)