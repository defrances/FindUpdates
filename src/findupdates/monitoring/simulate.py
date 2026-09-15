"""Synthetic post-update telemetry. Fixtures contain no patient data."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta

from findupdates.ids import stable_id
from findupdates.monitoring.models import HealthDomain, HealthObservation, HealthState

_DOMAINS: tuple[HealthDomain, ...] = (
    HealthDomain.INSTALL_SUCCESS,
    HealthDomain.BOOT,
    HealthDomain.WINDOWS_SERVICE,
    HealthDomain.MEDICAL_APPLICATION,
    HealthDomain.PERIPHERAL_CONNECTIVITY,
    HealthDomain.NETWORK_CONNECTIVITY,
    HealthDomain.DRIVER_FIRMWARE,
    HealthDomain.RESOURCES,
    HealthDomain.CLINICAL_SMOKE,
    HealthDomain.HEARTBEAT,
)
_BEFORE = "10.0.19045.4840"
_AFTER = "10.0.19045.5011"


def simulate_healthy(
    device_ids: Sequence[str],
    *,
    stage: str,
    now: datetime,
) -> tuple[HealthObservation, ...]:
    """All required domains HEALTHY with a fresh heartbeat."""
    return _for_devices(device_ids, stage, now, HealthState.HEALTHY, now)


def simulate_boot_failure(
    device_ids: Sequence[str],
    *,
    stage: str,
    now: datetime,
) -> tuple[HealthObservation, ...]:
    return _override(device_ids, stage, now, HealthDomain.BOOT, HealthState.FAILED, "boot loop")


def simulate_app_crash_spike(
    device_ids: Sequence[str],
    *,
    stage: str,
    now: datetime,
) -> tuple[HealthObservation, ...]:
    return _override(
        device_ids,
        stage,
        now,
        HealthDomain.MEDICAL_APPLICATION,
        HealthState.FAILED,
        "crash rate above baseline",
    )


def simulate_connectivity_loss(
    device_ids: Sequence[str],
    *,
    stage: str,
    now: datetime,
) -> tuple[HealthObservation, ...]:
    return _override(
        device_ids,
        stage,
        now,
        HealthDomain.NETWORK_CONNECTIVITY,
        HealthState.FAILED,
        "required service unreachable",
    )


def simulate_missing_telemetry(
    device_ids: Sequence[str],
    *,
    stage: str,
    now: datetime,
) -> tuple[HealthObservation, ...]:
    """No observations: evaluate_stage treats members as missing telemetry."""
    del device_ids, stage, now
    return ()


def simulate_stale_heartbeat(
    device_ids: Sequence[str],
    *,
    stage: str,
    now: datetime,
) -> tuple[HealthObservation, ...]:
    stale = now - timedelta(hours=2)
    return _for_devices(device_ids, stage, now, HealthState.HEALTHY, stale)


def _override(
    device_ids: Sequence[str],
    stage: str,
    now: datetime,
    domain: HealthDomain,
    state: HealthState,
    detail: str,
) -> tuple[HealthObservation, ...]:
    rows = list(_for_devices(device_ids, stage, now, HealthState.HEALTHY, now))
    updated: list[HealthObservation] = []
    for item in rows:
        if item.domain is domain:
            updated.append(
                HealthObservation(
                    observation_id=item.observation_id,
                    device_id=item.device_id,
                    stage=item.stage,
                    domain=item.domain,
                    state=state,
                    observed_at=item.observed_at,
                    heartbeat_at=item.heartbeat_at,
                    detail=detail,
                    before_version=item.before_version,
                    after_version=item.after_version,
                )
            )
        else:
            updated.append(item)
    return tuple(updated)


def _for_devices(
    device_ids: Sequence[str],
    stage: str,
    now: datetime,
    state: HealthState,
    heartbeat_at: datetime,
) -> tuple[HealthObservation, ...]:
    rows: list[HealthObservation] = []
    for device_id in device_ids:
        for domain in _DOMAINS:
            rows.append(
                HealthObservation(
                    observation_id=stable_id("health-obs", device_id, stage, domain.value),
                    device_id=device_id,
                    stage=stage,
                    domain=domain,
                    state=state,
                    observed_at=now,
                    heartbeat_at=heartbeat_at,
                    detail=f"simulated {domain.value}={state.value}",
                    before_version=_BEFORE,
                    after_version=_AFTER,
                )
            )
    return tuple(rows)
