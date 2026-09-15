"""JSON serialization for rollout plans and execution state."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from findupdates.rollout.models import (
    SCHEMA_VERSION,
    EmergencyOverride,
    HealthSignals,
    PromotionEvent,
    RolloutPlan,
    RolloutState,
    RolloutStatus,
    StageResult,
    StageSpec,
    StageStatus,
)


def plan_to_dict(plan: RolloutPlan) -> dict[str, Any]:
    """Schema-compatible rollout plan mapping."""
    return {
        "schema_version": SCHEMA_VERSION,
        "plan_id": plan.plan_id,
        "change_idempotency_key": plan.change_idempotency_key,
        "policy_result": plan.policy_result,
        "package_id": plan.package_id,
        "package_sha256": plan.package_sha256,
        "stages": [_stage_spec(item) for item in plan.stages],
        "membership_hash": plan.membership_hash,
        "emergency": {
            "authorized": plan.emergency.authorized,
            "actor": plan.emergency.actor,
            "reason": plan.emergency.reason,
        },
        "created_at": _datetime(plan.created_at),
    }


def state_to_dict(state: RolloutState) -> dict[str, Any]:
    """Schema-compatible rollout state mapping."""
    return {
        "schema_version": SCHEMA_VERSION,
        "rollout_id": state.rollout_id,
        "plan_id": state.plan_id,
        "status": state.status.value,
        "current_stage": state.current_stage,
        "stages": [_stage_result(item) for item in state.stages],
        "promotions": [
            {
                "actor": item.actor,
                "reason": item.reason,
                "from_stage": item.from_stage,
                "to_stage": item.to_stage,
                "membership_hash": item.membership_hash,
                "at": _datetime(item.at),
            }
            for item in state.promotions
        ],
        "updated_at": _datetime(state.updated_at),
    }


def dict_to_plan(payload: dict[str, Any]) -> RolloutPlan:
    """Parse a stored plan. Membership hashes are taken as recorded."""
    emergency = payload["emergency"]
    return RolloutPlan(
        plan_id=str(payload["plan_id"]),
        change_idempotency_key=str(payload["change_idempotency_key"]),
        policy_result=str(payload["policy_result"]),
        package_id=str(payload["package_id"]),
        package_sha256=str(payload["package_sha256"]),
        stages=tuple(_parse_spec(item) for item in payload["stages"]),
        membership_hash=str(payload["membership_hash"]),
        emergency=EmergencyOverride(
            authorized=bool(emergency["authorized"]),
            actor=str(emergency["actor"]),
            reason=str(emergency["reason"]),
        ),
        created_at=_parse_datetime(str(payload["created_at"])),
        schema_version=str(payload.get("schema_version", SCHEMA_VERSION)),
    )


def dict_to_state(payload: dict[str, Any]) -> RolloutState:
    """Parse stored execution state so a workflow restart can resume."""
    return RolloutState(
        rollout_id=str(payload["rollout_id"]),
        plan_id=str(payload["plan_id"]),
        status=RolloutStatus(str(payload["status"])),
        current_stage=str(payload["current_stage"]),
        stages=tuple(_parse_result(item) for item in payload["stages"]),
        promotions=tuple(_parse_promotion(item) for item in payload.get("promotions", [])),
        updated_at=_parse_datetime(str(payload["updated_at"])),
        schema_version=str(payload.get("schema_version", SCHEMA_VERSION)),
    )


def _stage_spec(item: StageSpec) -> dict[str, object]:
    return {
        "name": item.name,
        "environment": item.environment,
        "member_device_ids": list(item.member_device_ids),
        "membership_hash": item.membership_hash,
        "observation_window_minutes": item.observation_window_minutes,
        "max_failure_rate": item.max_failure_rate,
        "max_crash_count": item.max_crash_count,
        "max_connectivity_loss": item.max_connectivity_loss,
        "max_validation_regressions": item.max_validation_regressions,
        "requires_approval": item.requires_approval,
        "maintenance_required": item.maintenance_required,
    }


def _stage_result(item: StageResult) -> dict[str, object]:
    return {
        "name": item.name,
        "status": item.status.value,
        "membership_hash": item.membership_hash,
        "deployment_id": item.deployment_id,
        "actor": item.actor,
        "reason": item.reason,
        "started_at": None if item.started_at is None else _datetime(item.started_at),
        "observation_ends_at": None
        if item.observation_ends_at is None
        else _datetime(item.observation_ends_at),
        "health": None if item.health is None else _health(item.health),
    }


def _health(item: HealthSignals) -> dict[str, object]:
    return {
        "observed": item.observed,
        "success_count": item.success_count,
        "failure_count": item.failure_count,
        "crash_count": item.crash_count,
        "connectivity_loss": item.connectivity_loss,
        "validation_regressions": item.validation_regressions,
        "inconclusive_critical": item.inconclusive_critical,
    }


def _parse_spec(value: object) -> StageSpec:
    if not isinstance(value, dict):
        raise ValueError("stage spec must be an object")
    return StageSpec(
        name=str(value["name"]),
        environment=str(value["environment"]),
        member_device_ids=tuple(str(item) for item in value["member_device_ids"]),
        membership_hash=str(value["membership_hash"]),
        observation_window_minutes=int(value["observation_window_minutes"]),
        max_failure_rate=float(value["max_failure_rate"]),
        max_crash_count=int(value["max_crash_count"]),
        max_connectivity_loss=int(value["max_connectivity_loss"]),
        max_validation_regressions=int(value["max_validation_regressions"]),
        requires_approval=bool(value["requires_approval"]),
        maintenance_required=bool(value["maintenance_required"]),
    )


def _parse_result(value: object) -> StageResult:
    if not isinstance(value, dict):
        raise ValueError("stage result must be an object")
    health = value.get("health")
    started = value.get("started_at")
    ends = value.get("observation_ends_at")
    return StageResult(
        name=str(value["name"]),
        status=StageStatus(str(value["status"])),
        membership_hash=str(value["membership_hash"]),
        deployment_id=None if value.get("deployment_id") is None else str(value["deployment_id"]),
        actor=None if value.get("actor") is None else str(value["actor"]),
        reason=None if value.get("reason") is None else str(value["reason"]),
        started_at=None if started is None else _parse_datetime(str(started)),
        observation_ends_at=None if ends is None else _parse_datetime(str(ends)),
        health=None if health is None else _parse_health(health),
    )


def _parse_health(value: object) -> HealthSignals:
    if not isinstance(value, dict):
        raise ValueError("health signals must be an object")
    return HealthSignals(
        observed=bool(value["observed"]),
        success_count=int(value["success_count"]),
        failure_count=int(value["failure_count"]),
        crash_count=int(value["crash_count"]),
        connectivity_loss=int(value["connectivity_loss"]),
        validation_regressions=int(value["validation_regressions"]),
        inconclusive_critical=int(value["inconclusive_critical"]),
    )


def _parse_promotion(value: object) -> PromotionEvent:
    if not isinstance(value, dict):
        raise ValueError("promotion event must be an object")
    return PromotionEvent(
        actor=str(value["actor"]),
        reason=str(value["reason"]),
        from_stage=str(value["from_stage"]),
        to_stage=str(value["to_stage"]),
        membership_hash=str(value["membership_hash"]),
        at=_parse_datetime(str(value["at"])),
    )


def _datetime(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return parsed
