"""Promotion health gates. Missing or INCONCLUSIVE critical signals fail closed."""

from __future__ import annotations

from datetime import datetime

from findupdates.rollout.errors import RolloutDenied
from findupdates.rollout.models import HealthSignals, StageResult, StageSpec, StageStatus


def assert_promotable(spec: StageSpec, result: StageResult, *, now: datetime) -> None:
    """Refuse promotion while observation, health or thresholds are not green."""
    if result.status is StageStatus.SKIPPED:
        return
    if result.status is not StageStatus.OBSERVING:
        raise RolloutDenied(f"stage {spec.name} is {result.status.value}, not observing")
    if result.observation_ends_at is None or now < result.observation_ends_at:
        raise RolloutDenied(f"observation window for {spec.name} is incomplete")
    if result.health is None or not result.health.observed:
        raise RolloutDenied(f"required health data for {spec.name} is missing")
    if result.membership_hash != spec.membership_hash:
        raise RolloutDenied(f"authorized membership for {spec.name} no longer matches the plan")
    _assert_thresholds(spec, result.health)


def breaches_threshold(spec: StageSpec, health: HealthSignals) -> bool:
    """True when failures, crashes or INCONCLUSIVE critical signals exceed the stage cap."""
    if not health.observed:
        return False
    if health.inconclusive_critical > 0:
        return True
    if health.failure_rate > spec.max_failure_rate:
        return True
    if health.crash_count > spec.max_crash_count:
        return True
    if health.connectivity_loss > spec.max_connectivity_loss:
        return True
    return health.validation_regressions > spec.max_validation_regressions


def _assert_thresholds(spec: StageSpec, health: HealthSignals) -> None:
    if health.inconclusive_critical > 0:
        raise RolloutDenied(f"INCONCLUSIVE critical monitoring on {spec.name} forbids promotion")
    if breaches_threshold(spec, health):
        raise RolloutDenied(f"health thresholds breached on {spec.name}")
