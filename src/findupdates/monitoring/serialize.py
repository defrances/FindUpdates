"""JSON serialization for health observations, summaries and decisions."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from findupdates.monitoring.models import (
    SCHEMA_VERSION,
    DeviceHealth,
    HealthDomain,
    HealthObservation,
    HealthState,
    MonitoringDecision,
    StageHealthSummary,
)


def observation_to_dict(item: HealthObservation) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "observation_id": item.observation_id,
        "device_id": item.device_id,
        "stage": item.stage,
        "domain": item.domain.value,
        "state": item.state.value,
        "observed_at": _datetime(item.observed_at),
        "heartbeat_at": None if item.heartbeat_at is None else _datetime(item.heartbeat_at),
        "detail": item.detail,
        "before_version": item.before_version,
        "after_version": item.after_version,
    }


def summary_to_dict(summary: StageHealthSummary) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "summary_id": summary.summary_id,
        "rollout_id": summary.rollout_id,
        "stage": summary.stage,
        "overall": summary.overall.value,
        "pause_rollout": summary.pause_rollout,
        "window_minutes": summary.window_minutes,
        "window_ends_at": _datetime(summary.window_ends_at),
        "reason_codes": list(summary.reason_codes),
        "devices": [
            {
                "device_id": item.device_id,
                "overall": item.overall.value,
                "stale_heartbeat": item.stale_heartbeat,
                "missing_telemetry": item.missing_telemetry,
                "failed_domains": list(item.failed_domains),
                "inconclusive_domains": list(item.inconclusive_domains),
            }
            for item in summary.devices
        ],
        "signals": {
            "observed": True,
            "success_count": summary.success_count,
            "failure_count": summary.failure_count,
            "crash_count": summary.crash_count,
            "connectivity_loss": summary.connectivity_loss,
            "validation_regressions": summary.validation_regressions,
            "inconclusive_critical": summary.inconclusive_critical,
        },
        "observed_at": _datetime(summary.observed_at),
    }


def dict_to_observation(payload: dict[str, Any]) -> HealthObservation:
    heartbeat = payload.get("heartbeat_at")
    return HealthObservation(
        observation_id=str(payload["observation_id"]),
        device_id=str(payload["device_id"]),
        stage=str(payload["stage"]),
        domain=HealthDomain(str(payload["domain"])),
        state=HealthState(str(payload["state"])),
        observed_at=_parse_datetime(str(payload["observed_at"])),
        heartbeat_at=None if heartbeat is None else _parse_datetime(str(heartbeat)),
        detail=str(payload["detail"]),
        before_version=str(payload["before_version"]),
        after_version=str(payload["after_version"]),
        schema_version=str(payload.get("schema_version", SCHEMA_VERSION)),
    )


def dict_to_summary(payload: dict[str, Any]) -> StageHealthSummary:
    signals = payload["signals"]
    return StageHealthSummary(
        summary_id=str(payload["summary_id"]),
        rollout_id=str(payload["rollout_id"]),
        stage=str(payload["stage"]),
        overall=HealthState(str(payload["overall"])),
        pause_rollout=bool(payload["pause_rollout"]),
        window_minutes=int(payload["window_minutes"]),
        window_ends_at=_parse_datetime(str(payload["window_ends_at"])),
        reason_codes=tuple(str(item) for item in payload["reason_codes"]),
        devices=tuple(_parse_device(item) for item in payload["devices"]),
        success_count=int(signals["success_count"]),
        failure_count=int(signals["failure_count"]),
        crash_count=int(signals["crash_count"]),
        connectivity_loss=int(signals["connectivity_loss"]),
        validation_regressions=int(signals["validation_regressions"]),
        inconclusive_critical=int(signals["inconclusive_critical"]),
        observed_at=_parse_datetime(str(payload["observed_at"])),
        schema_version=str(payload.get("schema_version", SCHEMA_VERSION)),
    )


def decision_to_dict(item: MonitoringDecision) -> dict[str, Any]:
    return {
        "decision_id": item.decision_id,
        "action": item.action.value,
        "reason_codes": list(item.reason_codes),
        "evidence_ids": list(item.evidence_ids),
        "actor": item.actor,
        "at": _datetime(item.at),
        "rollback_outcome": item.rollback_outcome,
        "before_versions": [{"device_id": d, "version": v} for d, v in item.before_versions],
        "after_versions": [{"device_id": d, "version": v} for d, v in item.after_versions],
    }


def _parse_device(value: object) -> DeviceHealth:
    if not isinstance(value, dict):
        raise ValueError("device health must be an object")
    return DeviceHealth(
        device_id=str(value["device_id"]),
        overall=HealthState(str(value["overall"])),
        stale_heartbeat=bool(value["stale_heartbeat"]),
        missing_telemetry=bool(value["missing_telemetry"]),
        failed_domains=tuple(str(item) for item in value["failed_domains"]),
        inconclusive_domains=tuple(str(item) for item in value["inconclusive_domains"]),
    )


def _datetime(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return parsed
