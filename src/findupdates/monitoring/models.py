"""Post-deployment health observations and stage summaries."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

SCHEMA_VERSION = "1.0"

CRITICAL_DOMAINS = frozenset({"boot", "medical_application", "clinical_smoke", "heartbeat"})
_RANK = {
    "HEALTHY": 0,
    "DEGRADED": 1,
    "INCONCLUSIVE": 2,
    "FAILED": 3,
}


class HealthDomain(StrEnum):
    INSTALL_SUCCESS = "install_success"
    BOOT = "boot"
    WINDOWS_SERVICE = "windows_service"
    MEDICAL_APPLICATION = "medical_application"
    PERIPHERAL_CONNECTIVITY = "peripheral_connectivity"
    NETWORK_CONNECTIVITY = "network_connectivity"
    DRIVER_FIRMWARE = "driver_firmware"
    RESOURCES = "resources"
    CLINICAL_SMOKE = "clinical_smoke"
    HEARTBEAT = "heartbeat"


class HealthState(StrEnum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


class DecisionAction(StrEnum):
    PAUSE = "pause"
    PROMOTE_ALLOWED = "promote_allowed"
    PROMOTE_BLOCKED = "promote_blocked"
    ROLLBACK_OFFERED = "rollback_offered"
    ROLLBACK_DENIED = "rollback_denied"
    ROLLBACK_EXECUTED = "rollback_executed"
    ROLLBACK_PARTIAL = "rollback_partial"
    RESUME_READY = "resume_ready"


@dataclass(frozen=True, slots=True)
class HealthObservation:
    observation_id: str
    device_id: str
    stage: str
    domain: HealthDomain
    state: HealthState
    observed_at: datetime
    heartbeat_at: datetime | None
    detail: str
    before_version: str
    after_version: str
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
        if not self.device_id.strip() or not self.detail.strip():
            raise ValueError("observation device_id and detail must not be empty")
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")
        if self.heartbeat_at is not None and self.heartbeat_at.tzinfo is None:
            raise ValueError("heartbeat_at must be timezone-aware")
        if not self.before_version.strip() or not self.after_version.strip():
            raise ValueError("before/after versions must not be empty")


@dataclass(frozen=True, slots=True)
class DeviceHealth:
    device_id: str
    overall: HealthState
    stale_heartbeat: bool
    missing_telemetry: bool
    failed_domains: tuple[str, ...]
    inconclusive_domains: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StageHealthSummary:
    summary_id: str
    rollout_id: str
    stage: str
    overall: HealthState
    pause_rollout: bool
    window_minutes: int
    window_ends_at: datetime
    reason_codes: tuple[str, ...]
    devices: tuple[DeviceHealth, ...]
    success_count: int
    failure_count: int
    crash_count: int
    connectivity_loss: int
    validation_regressions: int
    inconclusive_critical: int
    observed_at: datetime
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
        if not self.devices:
            raise ValueError("stage health summary requires device outcomes")
        if not self.reason_codes:
            raise ValueError("stage health summary requires reason codes")
        if self.window_ends_at.tzinfo is None or self.observed_at.tzinfo is None:
            raise ValueError("summary timestamps must be timezone-aware")


@dataclass(frozen=True, slots=True)
class MonitoringDecision:
    decision_id: str
    action: DecisionAction
    reason_codes: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    actor: str
    at: datetime
    rollback_outcome: str | None
    before_versions: tuple[tuple[str, str], ...]
    after_versions: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if not self.actor.strip() or not self.reason_codes:
            raise ValueError("monitoring decision requires actor and reason codes")
        if self.at.tzinfo is None:
            raise ValueError("decision timestamp must be timezone-aware")


def worst_state(*states: HealthState) -> HealthState:
    """Return the most severe health state. INCONCLUSIVE outranks DEGRADED."""
    if not states:
        return HealthState.INCONCLUSIVE
    return max(states, key=lambda item: _RANK[item.value])
