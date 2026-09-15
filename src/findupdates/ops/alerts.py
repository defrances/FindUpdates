"""Observable alerts. Loss of telemetry never becomes a healthy signal."""

from __future__ import annotations

from datetime import datetime

from findupdates.ops.models import (
    Alert,
    AlertCode,
    FreshnessState,
    FreshnessVerdict,
    SourceObservation,
)


class AlertBus:
    """Collect operational alerts for tests, dashboards and notification adapters."""

    def __init__(self) -> None:
        self._alerts: list[Alert] = []

    def emit(self, alert: Alert) -> Alert:
        self._alerts.append(alert)
        return alert

    def alerts(self) -> tuple[Alert, ...]:
        return tuple(self._alerts)

    def codes(self) -> tuple[AlertCode, ...]:
        return tuple(item.code for item in self._alerts)


def alert_for_freshness(
    verdict: FreshnessVerdict,
    observation: SourceObservation,
    *,
    correlation_id: str,
    now: datetime,
) -> Alert | None:
    if verdict.healthy:
        return None
    if verdict.state is FreshnessState.UNOBSERVED:
        code = AlertCode.SOURCE_UNOBSERVED
        summary = f"{observation.source} has never completed a successful fetch"
    else:
        code = AlertCode.SOURCE_STALE
        summary = f"{observation.source} exceeded the {verdict.window_hours}h freshness window"
    if observation.last_error:
        code = AlertCode.COLLECTOR_FAILED
        summary = f"{observation.source} collector failed: {observation.last_error}"
    return Alert(
        code=code,
        correlation_id=correlation_id,
        summary=summary,
        source=observation.source,
        advisory_id=None,
        recorded_at=now,
    )


def alert_deployment_failed(
    *,
    correlation_id: str,
    advisory_id: str,
    reason: str,
    now: datetime,
) -> Alert:
    return Alert(
        code=AlertCode.DEPLOYMENT_FAILED,
        correlation_id=correlation_id,
        summary=reason,
        source="deployment",
        advisory_id=advisory_id,
        recorded_at=now,
    )


def alert_observability_missing(
    *,
    correlation_id: str,
    advisory_id: str,
    now: datetime,
) -> Alert:
    return Alert(
        code=AlertCode.OBSERVABILITY_MISSING,
        correlation_id=correlation_id,
        summary="required pipeline stage metrics are missing; not healthy",
        source=None,
        advisory_id=advisory_id,
        recorded_at=now,
    )
