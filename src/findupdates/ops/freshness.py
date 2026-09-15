"""Source freshness. Unobserved or stale feeds are not a healthy catalog."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from findupdates.ops.config import freshness_hours
from findupdates.ops.models import FreshnessState, FreshnessVerdict, SourceObservation


def evaluate_freshness(
    observation: SourceObservation,
    config: dict[str, Any],
    *,
    now: datetime,
) -> FreshnessVerdict:
    window = freshness_hours(config, observation.source)
    if observation.last_success_at is None:
        return FreshnessVerdict(
            source=observation.source,
            state=FreshnessState.UNOBSERVED,
            window_hours=window,
            healthy=False,
        )
    stale = now - observation.last_success_at > timedelta(hours=window)
    if stale or observation.last_error:
        return FreshnessVerdict(
            source=observation.source,
            state=FreshnessState.STALE,
            window_hours=window,
            healthy=False,
        )
    return FreshnessVerdict(
        source=observation.source,
        state=FreshnessState.FRESH,
        window_hours=window,
        healthy=True,
    )
