"""Lookback window for collector index selection and advisory emission."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from findupdates.normalization.models import UpdateAdvisory

_MIN_USABLE_YEAR = 2000


def window_start(retrieved_at: datetime, lookback: timedelta) -> datetime:
    """Inclusive UTC midnight of (retrieved_at - lookback)."""
    start = retrieved_at.astimezone(UTC) - lookback
    return start.replace(hour=0, minute=0, second=0, microsecond=0)


def in_lookback(value: datetime | None, *, retrieved_at: datetime, lookback: timedelta) -> bool:
    """True when the timestamp is dated inside the lookback window."""
    if value is None or value.year < _MIN_USABLE_YEAR or value.tzinfo is None:
        return False
    return value.astimezone(UTC) >= window_start(retrieved_at, lookback)


def advisory_in_lookback(
    advisory: UpdateAdvisory, *, retrieved_at: datetime, lookback: timedelta
) -> bool:
    """Use revised_at when present so a weekly revision is not dropped."""
    event = advisory.revised_at or advisory.published_at
    return in_lookback(event, retrieved_at=retrieved_at, lookback=lookback)
