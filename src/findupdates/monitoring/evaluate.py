"""Aggregate per-device observations. Stale or missing telemetry is not HEALTHY."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any

from findupdates.ids import stable_id
from findupdates.monitoring.config import (
    critical_domains,
    load_monitoring_config,
    observation_window_minutes,
    pause_states,
)
from findupdates.monitoring.models import (
    CRITICAL_DOMAINS,
    DeviceHealth,
    HealthDomain,
    HealthObservation,
    HealthState,
    StageHealthSummary,
    worst_state,
)
from findupdates.rollout.models import HealthSignals

_DOMAIN_REASONS = {
    HealthDomain.BOOT: "BOOT_FAILED",
    HealthDomain.MEDICAL_APPLICATION: "APP_CRASH_SPIKE",
    HealthDomain.NETWORK_CONNECTIVITY: "CONNECTIVITY_LOSS",
    HealthDomain.PERIPHERAL_CONNECTIVITY: "CONNECTIVITY_LOSS",
    HealthDomain.CLINICAL_SMOKE: "CLINICAL_SMOKE_FAILED",
    HealthDomain.RESOURCES: "RESOURCE_REGRESSION",
    HealthDomain.DRIVER_FIRMWARE: "DRIVER_FIRMWARE_INIT_FAILED",
    HealthDomain.INSTALL_SUCCESS: "INSTALL_FAILED",
    HealthDomain.WINDOWS_SERVICE: "SERVICE_UNHEALTHY",
    HealthDomain.HEARTBEAT: "STALE_HEARTBEAT",
}


def evaluate_stage(
    observations: Sequence[HealthObservation],
    *,
    rollout_id: str,
    stage: str,
    member_ids: Sequence[str],
    now: datetime,
    update_kind: str,
    clinical_criticality: str,
    config: dict[str, Any] | None = None,
) -> StageHealthSummary:
    """Build a stage summary. Missing members are INCONCLUSIVE, never HEALTHY."""
    document = config or load_monitoring_config()
    critical = critical_domains(document)
    max_age = timedelta(minutes=int(document["heartbeat_max_age_minutes"]))
    window = observation_window_minutes(
        document, update_kind=update_kind, clinical_criticality=clinical_criticality
    )
    by_device = _index(observations, stage)
    devices = [
        _device_health(device_id, by_device.get(device_id, ()), now, max_age, critical)
        for device_id in member_ids
    ]
    overall = (
        worst_state(*(item.overall for item in devices)) if devices else HealthState.INCONCLUSIVE
    )
    crash = sum(
        1 for item in devices if HealthDomain.MEDICAL_APPLICATION.value in item.failed_domains
    )
    connectivity = sum(
        1
        for item in devices
        if HealthDomain.NETWORK_CONNECTIVITY.value in item.failed_domains
        or HealthDomain.PERIPHERAL_CONNECTIVITY.value in item.failed_domains
    )
    clinical = sum(
        1 for item in devices if HealthDomain.CLINICAL_SMOKE.value in item.failed_domains
    )
    inconclusive = sum(
        1
        for item in devices
        if item.overall is HealthState.INCONCLUSIVE
        or any(domain in {item.value for item in critical} for domain in item.inconclusive_domains)
    )
    return StageHealthSummary(
        summary_id=stable_id("health-sum", rollout_id, stage, now.isoformat()),
        rollout_id=rollout_id,
        stage=stage,
        overall=overall,
        pause_rollout=overall in pause_states(document),
        window_minutes=window,
        window_ends_at=now + timedelta(minutes=window),
        reason_codes=_reasons(devices, overall),
        devices=tuple(devices),
        success_count=sum(1 for item in devices if item.overall is HealthState.HEALTHY),
        failure_count=sum(1 for item in devices if item.overall is HealthState.FAILED),
        crash_count=crash,
        connectivity_loss=connectivity,
        validation_regressions=clinical,
        inconclusive_critical=inconclusive,
        observed_at=now,
    )


def to_signals(summary: StageHealthSummary) -> HealthSignals:
    """Project a summary onto the rollout threshold counters."""
    failure = summary.failure_count
    inconclusive = summary.inconclusive_critical
    if summary.pause_rollout:
        if summary.overall is HealthState.INCONCLUSIVE:
            inconclusive = max(inconclusive, 1)
        else:
            failure = max(failure, 1)
    return HealthSignals(
        observed=True,
        success_count=summary.success_count,
        failure_count=failure,
        crash_count=summary.crash_count,
        connectivity_loss=summary.connectivity_loss,
        validation_regressions=summary.validation_regressions,
        inconclusive_critical=inconclusive,
    )


def _index(
    observations: Sequence[HealthObservation], stage: str
) -> dict[str, tuple[HealthObservation, ...]]:
    grouped: dict[str, list[HealthObservation]] = {}
    for item in observations:
        if item.stage != stage:
            continue
        grouped.setdefault(item.device_id, []).append(item)
    return {key: tuple(value) for key, value in grouped.items()}


def _device_health(
    device_id: str,
    observations: tuple[HealthObservation, ...],
    now: datetime,
    max_age: timedelta,
    critical: frozenset[HealthDomain],
) -> DeviceHealth:
    if not observations:
        return DeviceHealth(
            device_id=device_id,
            overall=HealthState.INCONCLUSIVE,
            stale_heartbeat=True,
            missing_telemetry=True,
            failed_domains=(),
            inconclusive_domains=(HealthDomain.HEARTBEAT.value,),
        )
    stale = _stale_heartbeat(observations, now, max_age)
    states = [item.state for item in observations]
    if stale:
        states.append(HealthState.INCONCLUSIVE)
    failed = tuple(item.domain.value for item in observations if item.state is HealthState.FAILED)
    inconclusive = [
        item.domain.value for item in observations if item.state is HealthState.INCONCLUSIVE
    ]
    if stale and HealthDomain.HEARTBEAT.value not in inconclusive:
        inconclusive.append(HealthDomain.HEARTBEAT.value)
    overall = worst_state(*states)
    if stale:
        overall = worst_state(overall, HealthState.INCONCLUSIVE)
    if any(domain.value in inconclusive for domain in critical):
        overall = worst_state(overall, HealthState.INCONCLUSIVE)
    return DeviceHealth(
        device_id=device_id,
        overall=overall,
        stale_heartbeat=stale,
        missing_telemetry=False,
        failed_domains=failed,
        inconclusive_domains=tuple(dict.fromkeys(inconclusive)),
    )


def _stale_heartbeat(
    observations: tuple[HealthObservation, ...],
    now: datetime,
    max_age: timedelta,
) -> bool:
    beats = [item.heartbeat_at for item in observations if item.heartbeat_at is not None]
    if not beats:
        return True
    return now - max(beats) > max_age


def _reasons(devices: Sequence[DeviceHealth], overall: HealthState) -> tuple[str, ...]:
    codes: list[str] = []
    if any(item.missing_telemetry for item in devices):
        codes.append("MISSING_TELEMETRY")
    if any(item.stale_heartbeat and not item.missing_telemetry for item in devices):
        codes.append("STALE_HEARTBEAT")
    for item in devices:
        for domain in item.failed_domains:
            codes.append(_DOMAIN_REASONS[HealthDomain(domain)])
        if any(domain in CRITICAL_DOMAINS for domain in item.inconclusive_domains):
            codes.append("INCONCLUSIVE_CRITICAL")
    if overall is HealthState.HEALTHY:
        codes.append("HEALTHY")
    elif overall is HealthState.DEGRADED:
        codes.append("THRESHOLD_BREACH")
    return tuple(dict.fromkeys(codes)) or ("INCONCLUSIVE_CRITICAL",)
