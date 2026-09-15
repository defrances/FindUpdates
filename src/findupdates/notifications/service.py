"""Severity-aware notification dispatch, acknowledgement and escalation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol

from findupdates.applicability.models import ApplicabilityResult
from findupdates.changerecords.models import ChangeRecord
from findupdates.inventory.models import DeviceInventory
from findupdates.normalization.models import UpdateAdvisory
from findupdates.notifications.build import build_advisory_event, build_operational_failure
from findupdates.notifications.channels import ChannelAdapter
from findupdates.notifications.models import (
    AssessmentState,
    DeliveryAttempt,
    DeliveryStatus,
    NotificationEvent,
    NotificationKind,
    NotifyResult,
    RoutingPolicy,
)
from findupdates.notifications.policy import load_routing_policy
from findupdates.risk.models import RiskAssessment


class NotificationLog(Protocol):
    def last_state(self, idempotency_key: str) -> AssessmentState | None: ...

    def last_fingerprint(self, idempotency_key: str) -> str | None: ...

    def record(self, event: NotificationEvent, deliveries: tuple[DeliveryAttempt, ...]) -> None: ...

    def acknowledge(self, event_id: str, *, actor: str, now: datetime) -> NotificationEvent: ...

    def unacknowledged(self) -> tuple[NotificationEvent, ...]: ...

    def delivered_since(self, *, severity: str, since: datetime) -> int: ...


@dataclass
class MemoryNotificationLog:
    """Process-local log for tests and single-process MVP runs."""

    events: dict[str, NotificationEvent] = field(default_factory=dict)
    fingerprints: dict[str, str] = field(default_factory=dict)
    states: dict[str, AssessmentState] = field(default_factory=dict)
    deliveries: list[tuple[str, DeliveryAttempt]] = field(default_factory=list)
    acks: dict[str, datetime] = field(default_factory=dict)

    def last_state(self, idempotency_key: str) -> AssessmentState | None:
        return self.states.get(idempotency_key)

    def last_fingerprint(self, idempotency_key: str) -> str | None:
        return self.fingerprints.get(idempotency_key)

    def record(self, event: NotificationEvent, deliveries: tuple[DeliveryAttempt, ...]) -> None:
        self.events[event.event_id] = event
        if any(item.status is DeliveryStatus.DELIVERED for item in deliveries):
            self.fingerprints[event.change_idempotency_key] = event.fingerprint
            self.states[event.change_idempotency_key] = event.current_state()
        for item in deliveries:
            self.deliveries.append((event.event_id, item))

    def acknowledge(self, event_id: str, *, actor: str, now: datetime) -> NotificationEvent:
        del actor
        event = self.events.get(event_id)
        if event is None:
            raise KeyError(event_id)
        updated = NotificationEvent(
            event_id=event.event_id,
            kind=event.kind,
            fingerprint=event.fingerprint,
            severity=event.severity,
            advisory_ids=event.advisory_ids,
            cve_ids=event.cve_ids,
            package_ids=event.package_ids,
            vendor=event.vendor,
            risk_score=event.risk_score,
            policy_result=event.policy_result,
            reason_codes=event.reason_codes,
            affected_device_count=event.affected_device_count,
            deployment_groups=event.deployment_groups,
            device_models=event.device_models,
            applicability_confidence=event.applicability_confidence,
            applicability_unknowns=event.applicability_unknowns,
            recommended_next_action=event.recommended_next_action,
            workflow_state=event.workflow_state,
            change_record_url=event.change_record_url,
            change_idempotency_key=event.change_idempotency_key,
            acknowledgement_required=event.acknowledgement_required,
            acknowledged=True,
            previous_state=event.previous_state,
            created_at=event.created_at,
        )
        self.events[event_id] = updated
        self.acks[event_id] = now
        return updated

    def unacknowledged(self) -> tuple[NotificationEvent, ...]:
        return tuple(
            item
            for item in self.events.values()
            if item.acknowledgement_required and not item.acknowledged
        )

    def delivered_since(self, *, severity: str, since: datetime) -> int:
        count = 0
        for event in self.events.values():
            if (
                event.severity == severity
                and event.created_at >= since
                and event.kind is NotificationKind.ADVISORY
            ):
                count += 1
        return count


class NotificationService:
    """Fan-out to configured channels. Does not change risk or policy."""

    def __init__(
        self,
        channels: dict[str, ChannelAdapter],
        *,
        policy: RoutingPolicy | None = None,
        log: NotificationLog | None = None,
    ) -> None:
        self._channels = channels
        self._policy = policy or load_routing_policy()
        self._log = log or MemoryNotificationLog()

    def notify_advisory(
        self,
        advisory: UpdateAdvisory,
        devices: tuple[DeviceInventory, ...],
        applicability: tuple[ApplicabilityResult, ...],
        risk: tuple[RiskAssessment, ...],
        change: ChangeRecord,
        *,
        now: datetime,
        change_record_url: str,
    ) -> NotifyResult:
        """Emit at most one logical notification for this assessment snapshot."""
        previous = self._log.last_state(change.idempotency_key)
        event = build_advisory_event(
            advisory,
            devices,
            applicability,
            risk,
            change,
            now=now,
            policy=self._policy,
            change_record_url=change_record_url,
            previous=previous,
        )
        if self._log.last_fingerprint(change.idempotency_key) == event.fingerprint:
            return NotifyResult(event, (), True)
        if event.severity in self._policy.low_priority_severities:
            window = timedelta(minutes=self._policy.low_priority_batch_window_minutes)
            already = self._log.delivered_since(severity=event.severity, since=now - window)
            if already >= self._policy.low_priority_rate_limit:
                digest = NotificationEvent(
                    event_id=f"{event.event_id}-digest",
                    kind=NotificationKind.DIGEST,
                    fingerprint=event.fingerprint,
                    severity=event.severity,
                    advisory_ids=event.advisory_ids,
                    cve_ids=event.cve_ids,
                    package_ids=event.package_ids,
                    vendor=event.vendor,
                    risk_score=event.risk_score,
                    policy_result=event.policy_result,
                    reason_codes=event.reason_codes,
                    affected_device_count=event.affected_device_count,
                    deployment_groups=event.deployment_groups,
                    device_models=event.device_models,
                    applicability_confidence=event.applicability_confidence,
                    applicability_unknowns=event.applicability_unknowns,
                    recommended_next_action=(
                        "Low-priority events exceeded the rate limit; review the digest "
                        "on the GitHub change record."
                    ),
                    workflow_state=event.workflow_state,
                    change_record_url=event.change_record_url,
                    change_idempotency_key=event.change_idempotency_key,
                    acknowledgement_required=False,
                    acknowledged=False,
                    previous_state=event.previous_state,
                    created_at=event.created_at,
                )
                deliveries = self._deliver(digest)
                self._log.record(digest, deliveries)
                return NotifyResult(digest, deliveries, False)
        return self._emit(event)

    def notify_operational_failure(
        self,
        change: ChangeRecord,
        *,
        now: datetime,
        change_record_url: str,
        reason: str,
    ) -> NotifyResult:
        """Always notify failed validation or deployment; this is a material change."""
        previous = self._log.last_state(change.idempotency_key)
        event = build_operational_failure(
            change,
            now=now,
            policy=self._policy,
            change_record_url=change_record_url,
            reason=reason,
            previous=previous,
        )
        if self._log.last_fingerprint(change.idempotency_key) == event.fingerprint:
            return NotifyResult(event, (), True)
        return self._emit(event)

    def publish(self, event: NotificationEvent) -> NotifyResult:
        """Emit an already-built event (used by post-deploy monitoring)."""
        if self._log.last_fingerprint(event.change_idempotency_key) == event.fingerprint:
            return NotifyResult(event, (), True)
        return self._emit(event)

    def acknowledge(self, event_id: str, *, actor: str, now: datetime) -> NotificationEvent:
        """Record that a human saw a severity that requires acknowledgement."""
        if not actor.strip():
            raise ValueError("acknowledgement actor must not be empty")
        return self._log.acknowledge(event_id, actor=actor.strip(), now=now)

    def escalate(self, *, now: datetime) -> tuple[NotifyResult, ...]:
        """Emit follow-up events for unacknowledged critical notifications."""
        results: list[NotifyResult] = []
        for event in self._log.unacknowledged():
            minutes = self._policy.escalate_after_minutes.get(event.severity)
            if minutes is None:
                continue
            if now < event.created_at + timedelta(minutes=minutes):
                continue
            follow = NotificationEvent(
                event_id=event.event_id + "-esc",
                kind=NotificationKind.ESCALATION,
                fingerprint=event.fingerprint + "-esc",
                severity=event.severity,
                advisory_ids=event.advisory_ids,
                cve_ids=event.cve_ids,
                package_ids=event.package_ids,
                vendor=event.vendor,
                risk_score=event.risk_score,
                policy_result=event.policy_result,
                reason_codes=(*event.reason_codes, "UNACKNOWLEDGED"),
                affected_device_count=event.affected_device_count,
                deployment_groups=event.deployment_groups,
                device_models=event.device_models,
                applicability_confidence=event.applicability_confidence,
                applicability_unknowns=event.applicability_unknowns,
                recommended_next_action="Unacknowledged critical notification. Escalate review.",
                workflow_state=event.workflow_state,
                change_record_url=event.change_record_url,
                change_idempotency_key=event.change_idempotency_key,
                acknowledgement_required=True,
                acknowledged=False,
                previous_state=event.current_state(),
                created_at=now,
            )
            results.append(self._emit(follow))
        return tuple(results)

    def _emit(self, event: NotificationEvent) -> NotifyResult:
        deliveries = self._deliver(event)
        self._log.record(event, deliveries)
        return NotifyResult(event, deliveries, False)

    def _deliver(self, event: NotificationEvent) -> tuple[DeliveryAttempt, ...]:
        names = self._policy.channels_for(event.severity)
        if event.kind is NotificationKind.OPERATIONAL_FAILURE and not names:
            names = ("github",)
        attempts: list[DeliveryAttempt] = []
        for name in names:
            adapter = self._channels.get(name)
            if adapter is None:
                attempts.append(
                    DeliveryAttempt(name, DeliveryStatus.FAILED, 0, "channel not configured")
                )
                continue
            attempts.append(adapter.send(event, attempts=self._policy.retry_attempts))
        return tuple(attempts)
