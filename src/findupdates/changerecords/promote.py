"""Lifecycle promotion rules. Workflow inputs cannot override policy."""

from __future__ import annotations

from datetime import datetime

from findupdates.changerecords.models import (
    ChangeRecord,
    LifecycleState,
    OverrideEvent,
    PromotionDenied,
    blocks_promotion,
)

_DEPLOYING = frozenset(
    {
        LifecycleState.CANARY,
        LifecycleState.STAGED_ROLLOUT,
        LifecycleState.COMPLETED,
    }
)

_ALLOWED_TARGETS = {
    "lab": LifecycleState.VALIDATION_PASSED,
    "canary": LifecycleState.CANARY,
    "production": LifecycleState.STAGED_ROLLOUT,
}


def promote(
    record: ChangeRecord,
    *,
    target_environment: str,
    actor: str,
    reason: str,
    now: datetime,
    environment_approved: bool,
) -> ChangeRecord:
    """Move a change record forward. HOLD/BLOCK cannot be promoted."""
    target = _ALLOWED_TARGETS.get(target_environment)
    if target is None:
        raise PromotionDenied(f"unknown environment {target_environment}")
    if blocks_promotion(record.policy_result) and target in _DEPLOYING:
        raise PromotionDenied(
            f"policy {record.policy_result} cannot be promoted to {target_environment}"
        )
    if target in _DEPLOYING and not environment_approved:
        raise PromotionDenied(
            f"{target_environment} requires GitHub Environment approval before promotion"
        )
    if target is LifecycleState.STAGED_ROLLOUT and record.lifecycle in {
        LifecycleState.HELD,
        LifecycleState.FAILED,
    }:
        raise PromotionDenied("held or failed records cannot enter staged rollout")
    override = OverrideEvent(
        actor=actor,
        timestamp=now,
        reason=reason,
        from_lifecycle=record.lifecycle,
        to_lifecycle=target,
    )
    return ChangeRecord(
        change_id=record.change_id,
        idempotency_key=record.idempotency_key,
        lifecycle=target,
        advisory_ids=record.advisory_ids,
        device_ids=record.device_ids,
        deployment_group=record.deployment_group,
        risk_score=record.risk_score,
        severity=record.severity,
        policy_result=record.policy_result,
        vendor=record.vendor,
        evidence_links=record.evidence_links,
        validation_plan=record.validation_plan,
        rollout_plan=record.rollout_plan,
        overrides=(*record.overrides, override),
        github_issue_number=record.github_issue_number,
        updated_at=now,
    )


def assert_workflow_gate(record: ChangeRecord, target_environment: str) -> None:
    """Fail closed for Actions. Does not read a caller-supplied policy value."""
    if blocks_promotion(record.policy_result) and target_environment in {"canary", "production"}:
        raise PromotionDenied(
            f"policy {record.policy_result} forbids {target_environment} promotion"
        )
    if target_environment not in _ALLOWED_TARGETS:
        raise PromotionDenied(f"unknown environment {target_environment}")
