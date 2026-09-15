"""Build notification events from deterministic pipeline records."""

from __future__ import annotations

from datetime import datetime

from findupdates.agents.redaction import redact_text
from findupdates.applicability.models import ApplicabilityResult, ApplicabilityVerdict
from findupdates.changerecords.models import ChangeRecord
from findupdates.ids import stable_id
from findupdates.inventory.models import DeviceInventory
from findupdates.normalization.models import UpdateAdvisory
from findupdates.notifications.models import (
    AssessmentState,
    NotificationEvent,
    NotificationKind,
    RoutingPolicy,
)
from findupdates.risk.models import RiskAssessment

_ACTIONS = {
    "BLOCK": "Do not deploy. Resolve unknown/blocking evidence on the GitHub change record.",
    "HOLD": "Hold the change. Complete the listed gates before requesting approval.",
    "REQUIRE_APPROVAL": (
        "Complete validation, then request the required GitHub Environment approval."
    ),
    "REQUIRE_VALIDATION": "Run lab validation against the listed devices before approval.",
    "ALLOW_ANALYSIS": "Analysis only. This notification does not authorize deployment.",
}


def build_advisory_event(
    advisory: UpdateAdvisory,
    devices: tuple[DeviceInventory, ...],
    applicability: tuple[ApplicabilityResult, ...],
    risk: tuple[RiskAssessment, ...],
    change: ChangeRecord,
    *,
    now: datetime,
    policy: RoutingPolicy,
    change_record_url: str,
    previous: AssessmentState | None = None,
    kind: NotificationKind = NotificationKind.ADVISORY,
) -> NotificationEvent:
    """Create one event. Patient identifiers are never copied onto the payload."""
    if not devices or not risk:
        raise ValueError("notification requires devices and risk assessments")
    worst = max(risk, key=lambda item: item.score)
    reason_codes = tuple(dict.fromkeys(code for item in risk for code in item.reason_codes))
    unknowns = tuple(
        dict.fromkeys(
            field
            for item in applicability
            for field in item.missing_data
            if item.verdict is ApplicabilityVerdict.UNKNOWN or item.missing_data
        )
    )
    confidences = {item.confidence.value for item in applicability}
    confidence = "mixed" if len(confidences) > 1 else next(iter(confidences), "unknown")
    models = tuple(dict.fromkeys(_safe_text(item.model) for item in devices))
    packages = tuple(dict.fromkeys(item.value for item in advisory.package_ids))
    fingerprint = event_fingerprint(
        change.idempotency_key,
        worst.severity.value,
        worst.policy_result.value,
        str(len(devices)),
        "kev" if "KEV" in reason_codes else "no-kev",
        change.lifecycle.value,
        kind.value,
    )
    return NotificationEvent(
        event_id=stable_id("notify", fingerprint, _datetime_key(now)),
        kind=kind,
        fingerprint=fingerprint,
        severity=worst.severity.value,
        advisory_ids=change.advisory_ids,
        cve_ids=advisory.cve_ids,
        package_ids=packages,
        vendor=advisory.vendor.value,
        risk_score=worst.score,
        policy_result=worst.policy_result.value,
        reason_codes=reason_codes,
        affected_device_count=len(devices),
        deployment_groups=tuple(dict.fromkeys(item.deployment_group for item in devices)),
        device_models=models,
        applicability_confidence=confidence,
        applicability_unknowns=unknowns,
        recommended_next_action=_ACTIONS.get(
            worst.policy_result.value, "Review the GitHub change record."
        ),
        workflow_state=change.lifecycle.value,
        change_record_url=_safe_url(change_record_url),
        change_idempotency_key=change.idempotency_key,
        acknowledgement_required=policy.requires_ack(worst.severity.value),
        acknowledged=False,
        previous_state=previous,
        created_at=now,
    )


def build_operational_failure(
    change: ChangeRecord,
    *,
    now: datetime,
    policy: RoutingPolicy,
    change_record_url: str,
    reason: str,
    previous: AssessmentState | None = None,
) -> NotificationEvent:
    """Alert operators that validation or deployment failed."""
    fingerprint = event_fingerprint(
        change.idempotency_key,
        change.severity,
        change.policy_result,
        str(len(change.device_ids)),
        "failure",
        change.lifecycle.value,
        NotificationKind.OPERATIONAL_FAILURE.value,
    )
    detail, _changed = redact_text(reason)
    return NotificationEvent(
        event_id=stable_id("notify", fingerprint, _datetime_key(now)),
        kind=NotificationKind.OPERATIONAL_FAILURE,
        fingerprint=fingerprint,
        severity=change.severity if change.severity in policy.channels else "HIGH",
        advisory_ids=change.advisory_ids,
        cve_ids=(),
        package_ids=(),
        vendor=change.vendor,
        risk_score=change.risk_score,
        policy_result=change.policy_result,
        reason_codes=("OPERATIONAL_FAILURE",),
        affected_device_count=len(change.device_ids),
        deployment_groups=(change.deployment_group,),
        device_models=(),
        applicability_confidence="unknown",
        applicability_unknowns=(),
        recommended_next_action=detail or "Inspect the failed validation or deployment job.",
        workflow_state=change.lifecycle.value,
        change_record_url=_safe_url(change_record_url),
        change_idempotency_key=change.idempotency_key,
        acknowledgement_required=True,
        acknowledged=False,
        previous_state=previous,
        created_at=now,
    )


def event_fingerprint(*parts: str) -> str:
    """Identity used to suppress unchanged rescans."""
    return stable_id("notify-fp", *parts)


def _safe_text(value: str) -> str:
    text, _changed = redact_text(value)
    return text or "unspecified"


def _safe_url(value: str) -> str:
    text, _changed = redact_text(value)
    if not text.strip():
        raise ValueError("change_record_url must not be empty")
    return text


def _datetime_key(value: datetime) -> str:
    return value.isoformat()
