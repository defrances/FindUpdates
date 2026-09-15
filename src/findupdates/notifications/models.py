"""Notification events, routing policy and delivery outcomes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

SCHEMA_VERSION = "1.0"

_SEVERITY_RANK = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
    "EMERGENCY": 4,
}


class NotificationKind(StrEnum):
    ADVISORY = "advisory"
    OPERATIONAL_FAILURE = "operational_failure"
    ESCALATION = "escalation"
    DIGEST = "digest"


class DeliveryStatus(StrEnum):
    DELIVERED = "delivered"
    FAILED = "failed"
    SUPPRESSED = "suppressed"
    BATCHED = "batched"


@dataclass(frozen=True, slots=True)
class AssessmentState:
    """Comparable snapshot used to detect material notification changes."""

    severity: str
    policy_result: str
    affected_device_count: int
    kev: bool
    workflow_state: str

    def __post_init__(self) -> None:
        if self.affected_device_count < 0:
            raise ValueError("affected_device_count must be >= 0")


@dataclass(frozen=True, slots=True)
class RoutingPolicy:
    version: str
    channels: dict[str, tuple[str, ...]]
    acknowledge_required: frozenset[str]
    escalate_after_minutes: dict[str, int]
    low_priority_severities: frozenset[str]
    low_priority_batch_window_minutes: int
    low_priority_rate_limit: int
    retry_attempts: int

    def channels_for(self, severity: str) -> tuple[str, ...]:
        return self.channels.get(severity, ())

    def requires_ack(self, severity: str) -> bool:
        return severity in self.acknowledge_required


@dataclass(frozen=True, slots=True)
class NotificationEvent:
    """Actionable, non-PHI notification tied to a GitHub change record."""

    event_id: str
    kind: NotificationKind
    fingerprint: str
    severity: str
    advisory_ids: tuple[str, ...]
    cve_ids: tuple[str, ...]
    package_ids: tuple[str, ...]
    vendor: str
    risk_score: int
    policy_result: str
    reason_codes: tuple[str, ...]
    affected_device_count: int
    deployment_groups: tuple[str, ...]
    device_models: tuple[str, ...]
    applicability_confidence: str
    applicability_unknowns: tuple[str, ...]
    recommended_next_action: str
    workflow_state: str
    change_record_url: str
    change_idempotency_key: str
    acknowledgement_required: bool
    acknowledged: bool
    previous_state: AssessmentState | None
    created_at: datetime
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score must be between 0 and 100")
        if self.severity not in _SEVERITY_RANK:
            raise ValueError(f"unknown severity {self.severity}")

    def current_state(self) -> AssessmentState:
        return AssessmentState(
            severity=self.severity,
            policy_result=self.policy_result,
            affected_device_count=self.affected_device_count,
            kev="KEV" in self.reason_codes,
            workflow_state=self.workflow_state,
        )


@dataclass(frozen=True, slots=True)
class DeliveryAttempt:
    channel: str
    status: DeliveryStatus
    attempts: int
    error: str | None = None


@dataclass(frozen=True, slots=True)
class NotifyResult:
    event: NotificationEvent | None
    deliveries: tuple[DeliveryAttempt, ...]
    suppressed: bool


def severity_increased(previous: AssessmentState, current: AssessmentState) -> bool:
    """Return whether the severity band moved to a more urgent value."""
    return _SEVERITY_RANK[current.severity] > _SEVERITY_RANK[previous.severity]


def is_material_change(previous: AssessmentState, current: AssessmentState) -> bool:
    """Changes that must notify again even if the advisory identity is unchanged."""
    if severity_increased(previous, current):
        return True
    if current.kev and not previous.kev:
        return True
    if current.affected_device_count > previous.affected_device_count:
        return True
    if current.policy_result != previous.policy_result:
        return True
    return current.workflow_state != previous.workflow_state and current.workflow_state in {
        "failed",
        "held",
    }
