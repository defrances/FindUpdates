"""Pause is the default. Automated rollback is offered only when explicitly safe."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any

from findupdates.deployment.models import AdapterCapabilities
from findupdates.ids import stable_id
from findupdates.monitoring.config import (
    load_monitoring_config,
    rollback_enabled_for,
    rollback_permitted_domains,
)
from findupdates.monitoring.errors import PromotionBlocked, ResumeDenied, RollbackDenied
from findupdates.monitoring.models import (
    DecisionAction,
    HealthDomain,
    HealthState,
    MonitoringDecision,
    StageHealthSummary,
)


def decide_pause(summary: StageHealthSummary, *, actor: str, now: datetime) -> MonitoringDecision:
    """Automatic pause when the stage is not HEALTHY."""
    action = DecisionAction.PAUSE if summary.pause_rollout else DecisionAction.PROMOTE_ALLOWED
    if summary.pause_rollout:
        codes = summary.reason_codes
    elif now < summary.window_ends_at:
        action = DecisionAction.PROMOTE_BLOCKED
        codes = (*summary.reason_codes, "WINDOW_INCOMPLETE")
    else:
        codes = summary.reason_codes
    return MonitoringDecision(
        decision_id=stable_id("mon-dec", summary.summary_id, action.value),
        action=action,
        reason_codes=codes,
        evidence_ids=(summary.summary_id,),
        actor=actor,
        at=now,
        rollback_outcome=None,
        before_versions=(),
        after_versions=(),
    )


def decide_rollback(
    summary: StageHealthSummary,
    capabilities: AdapterCapabilities,
    *,
    update_kind: str,
    critical_device_ids: Sequence[str],
    authorized: bool,
    actor: str,
    now: datetime,
    config: dict[str, Any] | None = None,
) -> MonitoringDecision:
    """Never auto-execute. Pause remains correct when rollback risk is unknown."""
    document = config or load_monitoring_config()
    codes = list(summary.reason_codes)
    if summary.overall is not HealthState.FAILED:
        codes.append("ROLLBACK_NOT_INDICATED")
        return _decision(summary, DecisionAction.ROLLBACK_DENIED, codes, actor, now, "not_offered")
    failed = {HealthDomain(domain) for item in summary.devices for domain in item.failed_domains}
    permitted = rollback_permitted_domains(document)
    if not failed.intersection(permitted):
        codes.append("ROLLBACK_NOT_INDICATED")
        return _decision(summary, DecisionAction.ROLLBACK_DENIED, codes, actor, now, "not_offered")
    if not capabilities.supports_rollback:
        codes.append("ROLLBACK_UNSUPPORTED")
        return _decision(summary, DecisionAction.ROLLBACK_DENIED, codes, actor, now, "unsupported")
    if not rollback_enabled_for(document, update_kind):
        codes.append("ROLLBACK_POLICY_DISABLED")
        return _decision(summary, DecisionAction.ROLLBACK_DENIED, codes, actor, now, "policy")
    members = {item.device_id for item in summary.devices}
    critical_hit = members.intersection(critical_device_ids)
    if critical_hit and not authorized:
        codes.append("ROLLBACK_CRITICAL_UNAPPROVED")
        return _decision(summary, DecisionAction.ROLLBACK_DENIED, codes, actor, now, "unapproved")
    return _decision(summary, DecisionAction.ROLLBACK_OFFERED, codes, actor, now, None)


def assert_promote_ready(summary: StageHealthSummary, *, now: datetime) -> None:
    """Healthy stages still wait for the configured observation window."""
    if summary.overall is not HealthState.HEALTHY or summary.pause_rollout:
        raise PromotionBlocked(
            f"promotion blocked on {summary.stage}: {', '.join(summary.reason_codes)}"
        )
    if now < summary.window_ends_at:
        raise PromotionBlocked(f"observation window for {summary.stage} is incomplete")
    if summary.inconclusive_critical:
        raise PromotionBlocked("INCONCLUSIVE critical health blocks promotion")


def assert_resume_ready(summary: StageHealthSummary, *, now: datetime) -> None:
    """Resume only after a healthy, fresh observation window."""
    if summary.overall is not HealthState.HEALTHY:
        raise ResumeDenied(f"resume requires HEALTHY stage, not {summary.overall.value}")
    if summary.inconclusive_critical:
        raise ResumeDenied("resume is blocked while critical telemetry is INCONCLUSIVE")
    if any(item.stale_heartbeat or item.missing_telemetry for item in summary.devices):
        raise ResumeDenied("resume is blocked while heartbeats are stale or missing")
    if now < summary.window_ends_at:
        raise ResumeDenied("recovery observation window is incomplete")


def require_rollback_offered(decision: MonitoringDecision) -> None:
    if decision.action is not DecisionAction.ROLLBACK_OFFERED:
        raise RollbackDenied(f"rollback is not authorized: {', '.join(decision.reason_codes)}")


def _decision(
    summary: StageHealthSummary,
    action: DecisionAction,
    codes: list[str],
    actor: str,
    now: datetime,
    outcome: str | None,
) -> MonitoringDecision:
    return MonitoringDecision(
        decision_id=stable_id("mon-dec", summary.summary_id, action.value),
        action=action,
        reason_codes=tuple(dict.fromkeys(codes)),
        evidence_ids=(summary.summary_id,),
        actor=actor,
        at=now,
        rollback_outcome=outcome,
        before_versions=(),
        after_versions=(),
    )
