"""Turn monitoring decisions into severity-aware operational notifications."""

from __future__ import annotations

from datetime import datetime

from findupdates.agents.redaction import redact_text
from findupdates.ids import stable_id
from findupdates.monitoring.models import MonitoringDecision, StageHealthSummary
from findupdates.notifications.build import event_fingerprint
from findupdates.notifications.models import NotificationEvent, NotificationKind, RoutingPolicy


def build_monitoring_event(
    summary: StageHealthSummary,
    decision: MonitoringDecision,
    *,
    now: datetime,
    policy: RoutingPolicy,
    change_record_url: str,
    change_idempotency_key: str,
    vendor: str,
    severity: str,
    package_ids: tuple[str, ...],
) -> NotificationEvent:
    """Notify a pause or rollback decision. Payloads stay non-PHI."""
    fingerprint = event_fingerprint(
        change_idempotency_key,
        summary.stage,
        decision.action.value,
        *decision.reason_codes,
        NotificationKind.OPERATIONAL_FAILURE.value,
    )
    detail, _changed = redact_text(
        f"{decision.action.value} on {summary.stage}: {', '.join(decision.reason_codes)}"
    )
    band = severity if severity in policy.channels else "HIGH"
    url, _redacted = redact_text(change_record_url)
    if not url.strip():
        raise ValueError("change_record_url must not be empty")
    return NotificationEvent(
        event_id=stable_id("notify", fingerprint, now.isoformat()),
        kind=NotificationKind.OPERATIONAL_FAILURE,
        fingerprint=fingerprint,
        severity=band,
        advisory_ids=(),
        cve_ids=(),
        package_ids=package_ids,
        vendor=vendor,
        risk_score=0 if summary.overall.value != "FAILED" else 80,
        policy_result="HOLD",
        reason_codes=decision.reason_codes,
        affected_device_count=len(summary.devices),
        deployment_groups=(summary.stage,),
        device_models=(),
        applicability_confidence="unknown",
        applicability_unknowns=(),
        recommended_next_action=detail or "Inspect the paused rollout before promoting.",
        workflow_state=decision.action.value,
        change_record_url=url,
        change_idempotency_key=change_idempotency_key,
        acknowledgement_required=True,
        acknowledged=False,
        previous_state=None,
        created_at=now,
    )
