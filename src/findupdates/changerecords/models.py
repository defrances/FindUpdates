"""Auditable change records used as the GitHub control-plane payload."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

SCHEMA_VERSION = "1.0"


class LifecycleState(StrEnum):
    DETECTED = "detected"
    ASSESSED = "assessed"
    VALIDATION_REQUESTED = "validation_requested"
    VALIDATION_PASSED = "validation_passed"
    AWAITING_APPROVAL = "awaiting_approval"
    CANARY = "canary"
    STAGED_ROLLOUT = "staged_rollout"
    COMPLETED = "completed"
    HELD = "held"
    FAILED = "failed"


class PromotionDenied(ValueError):
    """Raised when a lifecycle move would bypass a hard policy gate."""


@dataclass(frozen=True, slots=True)
class OverrideEvent:
    actor: str
    timestamp: datetime
    reason: str
    from_lifecycle: LifecycleState
    to_lifecycle: LifecycleState

    def __post_init__(self) -> None:
        if not self.actor.strip() or not self.reason.strip():
            raise ValueError("override actor and reason must not be empty")
        if self.timestamp.tzinfo is None:
            raise ValueError("override timestamp must be timezone-aware")


@dataclass(frozen=True, slots=True)
class ChangeRecord:
    """One logical advisory/scope change. GitHub Issues are the durable store."""

    change_id: str
    idempotency_key: str
    lifecycle: LifecycleState
    advisory_ids: tuple[str, ...]
    device_ids: tuple[str, ...]
    deployment_group: str
    risk_score: int
    severity: str
    policy_result: str
    vendor: str
    evidence_links: tuple[str, ...]
    validation_plan: str
    rollout_plan: str
    overrides: tuple[OverrideEvent, ...]
    github_issue_number: int | None
    updated_at: datetime
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {self.schema_version}")
        if not self.advisory_ids or not self.device_ids:
            raise ValueError("change record requires advisory and device ids")
        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score must be between 0 and 100")
        if self.updated_at.tzinfo is None:
            raise ValueError("updated_at must be timezone-aware")


def blocks_promotion(policy_result: str) -> bool:
    """HOLD and BLOCK cannot enter canary, staged rollout or completed."""
    return policy_result in {"HOLD", "BLOCK"}
