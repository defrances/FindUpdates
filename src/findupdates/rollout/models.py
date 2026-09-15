"""Staged rollout contracts. Membership is frozen at plan time."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

SCHEMA_VERSION = "1.0"
STAGE_ORDER = ("lab", "canary", "ring-1", "ring-2", "production")
_STAGE_ENV = {
    "lab": "lab",
    "canary": "canary",
    "ring-1": "canary",
    "ring-2": "production",
    "production": "production",
}
_CRITICAL = frozenset({"high", "critical"})
_BLOCKING_POLICY = frozenset({"HOLD", "BLOCK", "ALLOW_ANALYSIS"})
_WEEKDAYS = frozenset({"mon", "tue", "wed", "thu", "fri", "sat", "sun"})


class RolloutStatus(StrEnum):
    PLANNED = "planned"
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StageStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    OBSERVING = "observing"
    PASSED = "passed"
    FAILED = "failed"
    PAUSED = "paused"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class MaintenanceWindow:
    timezone: str
    days_of_week: tuple[str, ...]
    start_local: str
    duration_minutes: int

    def __post_init__(self) -> None:
        if not self.timezone.strip():
            raise ValueError("maintenance timezone must not be empty")
        if not self.days_of_week or any(day not in _WEEKDAYS for day in self.days_of_week):
            raise ValueError("maintenance days_of_week is invalid")
        hour, separator, minute = self.start_local.partition(":")
        if separator != ":" or not hour.isdigit() or not minute.isdigit():
            raise ValueError("start_local must be HH:MM")
        if not 0 <= int(hour) <= 23 or not 0 <= int(minute) <= 59:
            raise ValueError("start_local must be HH:MM")
        if not 1 <= self.duration_minutes <= 1440:
            raise ValueError("duration_minutes must be 1..1440")


@dataclass(frozen=True, slots=True)
class RolloutDevice:
    device_id: str
    model: str
    site: str
    clinical_criticality: str
    deployment_group: str
    backend: str
    maintenance: MaintenanceWindow

    def __post_init__(self) -> None:
        for value in (
            self.device_id,
            self.model,
            self.site,
            self.clinical_criticality,
            self.deployment_group,
            self.backend,
        ):
            if not value.strip():
                raise ValueError("rollout device fields must not be empty")

    @property
    def is_clinical_critical(self) -> bool:
        return self.clinical_criticality in _CRITICAL

    @property
    def is_lab(self) -> bool:
        return self.deployment_group.startswith("lab") or self.site == "lab"


@dataclass(frozen=True, slots=True)
class HealthSignals:
    observed: bool
    success_count: int
    failure_count: int
    crash_count: int
    connectivity_loss: int
    validation_regressions: int
    inconclusive_critical: int

    def __post_init__(self) -> None:
        for value in (
            self.success_count,
            self.failure_count,
            self.crash_count,
            self.connectivity_loss,
            self.validation_regressions,
            self.inconclusive_critical,
        ):
            if value < 0:
                raise ValueError("health counts must not be negative")

    @property
    def failure_rate(self) -> float:
        total = self.success_count + self.failure_count
        if total == 0:
            return 1.0 if self.observed else 0.0
        return self.failure_count / total


@dataclass(frozen=True, slots=True)
class EmergencyOverride:
    authorized: bool
    actor: str
    reason: str

    def __post_init__(self) -> None:
        if self.authorized and (not self.actor.strip() or not self.reason.strip()):
            raise ValueError("emergency override requires actor and reason")


@dataclass(frozen=True, slots=True)
class StageSpec:
    name: str
    environment: str
    member_device_ids: tuple[str, ...]
    membership_hash: str
    observation_window_minutes: int
    max_failure_rate: float
    max_crash_count: int
    max_connectivity_loss: int
    max_validation_regressions: int
    requires_approval: bool
    maintenance_required: bool

    def __post_init__(self) -> None:
        if self.name not in STAGE_ORDER:
            raise ValueError(f"unknown stage {self.name}")
        if self.environment != _STAGE_ENV[self.name]:
            raise ValueError(f"stage {self.name} must use environment {_STAGE_ENV[self.name]}")
        if len(self.membership_hash) != 64:
            raise ValueError("membership_hash must be a SHA-256 digest")
        if self.observation_window_minutes < 0:
            raise ValueError("observation_window_minutes must not be negative")


@dataclass(frozen=True, slots=True)
class RolloutPlan:
    plan_id: str
    change_idempotency_key: str
    policy_result: str
    package_id: str
    package_sha256: str
    stages: tuple[StageSpec, ...]
    membership_hash: str
    emergency: EmergencyOverride
    created_at: datetime
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
        if self.policy_result in _BLOCKING_POLICY:
            raise ValueError(f"policy {self.policy_result} cannot authorize a rollout")
        names = tuple(item.name for item in self.stages)
        if names != STAGE_ORDER:
            raise ValueError("rollout plan must contain lab through production in order")
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")

    def stage(self, name: str) -> StageSpec:
        return next(item for item in self.stages if item.name == name)


@dataclass(frozen=True, slots=True)
class StageResult:
    name: str
    status: StageStatus
    membership_hash: str
    deployment_id: str | None
    actor: str | None
    reason: str | None
    started_at: datetime | None
    observation_ends_at: datetime | None
    health: HealthSignals | None


@dataclass(frozen=True, slots=True)
class PromotionEvent:
    actor: str
    reason: str
    from_stage: str
    to_stage: str
    membership_hash: str
    at: datetime

    def __post_init__(self) -> None:
        if not self.actor.strip() or not self.reason.strip():
            raise ValueError("promotion actor and reason must not be empty")
        if self.at.tzinfo is None:
            raise ValueError("promotion timestamp must be timezone-aware")


@dataclass(frozen=True, slots=True)
class RolloutState:
    rollout_id: str
    plan_id: str
    status: RolloutStatus
    current_stage: str
    stages: tuple[StageResult, ...]
    promotions: tuple[PromotionEvent, ...]
    updated_at: datetime
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
        if self.updated_at.tzinfo is None:
            raise ValueError("updated_at must be timezone-aware")

    def stage_result(self, name: str) -> StageResult:
        return next(item for item in self.stages if item.name == name)


def stage_environment(name: str) -> str:
    """Map a rollout stage to the deployment-adapter environment."""
    try:
        return _STAGE_ENV[name]
    except KeyError as exc:
        raise ValueError(f"unknown stage {name}") from exc
