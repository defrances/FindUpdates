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


def msrc_advisory_in_lookback(
    advisory: UpdateAdvisory, *, retrieved_at: datetime, lookback: timedelta
) -> bool:
    """Monthly CVRF document dates are catalog stamps, not per-CVE events.

    A CVE without its own revision stays in the weekly window only when its
    CVE year is at least the lookback window's year. Older years are reprints.
    """
    if advisory.revised_at is not None:
        return advisory_in_lookback(advisory, retrieved_at=retrieved_at, lookback=lookback)
    year = cve_year(advisory)
    start = window_start(retrieved_at, lookback)
    if year is None or year < start.year:
        return False
    return advisory_in_lookback(advisory, retrieved_at=retrieved_at, lookback=lookback)


def cve_year(advisory: UpdateAdvisory) -> int | None:
    if not advisory.cve_ids:
        return None
    parts = advisory.cve_ids[0].split("-")
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None
