"""Apply stage health to rollout: auto-pause, notify, and gated rollback."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any

from findupdates.deployment.errors import PartialFailure, RollbackUnsupported
from findupdates.deployment.mock import MockDeploymentAdapter
from findupdates.deployment.models import AuthorizationEvidence, OidcCredential, PackageIdentity
from findupdates.monitoring.decide import (
    assert_promote_ready,
    assert_resume_ready,
    decide_pause,
    decide_rollback,
    require_rollback_offered,
)
from findupdates.monitoring.errors import RollbackDenied
from findupdates.monitoring.evaluate import evaluate_stage, to_signals
from findupdates.monitoring.models import (
    DecisionAction,
    HealthObservation,
    MonitoringDecision,
    StageHealthSummary,
)
from findupdates.monitoring.notify import build_monitoring_event
from findupdates.notifications.models import NotifyResult
from findupdates.notifications.policy import load_routing_policy
from findupdates.notifications.service import NotificationService
from findupdates.rollout.controller import RolloutController
from findupdates.rollout.models import RolloutState, RolloutStatus


class PostDeployMonitor:
    """Post-update observer. Pause is automatic; rollback is never implicit."""

    def __init__(
        self,
        *,
        update_kind: str = "os",
        clinical_criticality: str = "medium",
        notifications: NotificationService | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        self._update_kind = update_kind
        self._clinical = clinical_criticality
        self._notifications = notifications
        self._config = config
        self._policy = load_routing_policy()
        self.decisions: list[MonitoringDecision] = []
        self.alerts: list[NotifyResult] = []

    def ingest(
        self,
        controller: RolloutController,
        rollout_id: str,
        observations: Sequence[HealthObservation],
        *,
        now: datetime,
        actor: str,
        change_idempotency_key: str = "change_abc",
        change_record_url: str = "https://github.com/defrances/FindUpdates/issues/1",
        vendor: str = "microsoft",
        severity: str = "HIGH",
        package_ids: tuple[str, ...] = (),
    ) -> tuple[StageHealthSummary, MonitoringDecision, RolloutState]:
        """Evaluate telemetry, pause on breach, and notify operators."""
        state = controller.state(rollout_id)
        plan = controller.plan_for(rollout_id)
        spec = plan.stage(state.current_stage)
        summary = evaluate_stage(
            observations,
            rollout_id=rollout_id,
            stage=state.current_stage,
            member_ids=spec.member_device_ids,
            now=now,
            update_kind=self._update_kind,
            clinical_criticality=self._clinical,
            config=self._config,
        )
        decision = decide_pause(summary, actor=actor, now=now)
        if state.status is not RolloutStatus.PAUSED:
            state = controller.record_health(rollout_id, to_signals(summary), now=now)
        versions = _versions(observations)
        decision = MonitoringDecision(
            decision_id=decision.decision_id,
            action=decision.action,
            reason_codes=decision.reason_codes,
            evidence_ids=decision.evidence_ids,
            actor=decision.actor,
            at=decision.at,
            rollback_outcome=decision.rollback_outcome,
            before_versions=versions[0],
            after_versions=versions[1],
        )
        self.decisions.append(decision)
        if summary.pause_rollout:
            self._notify(
                summary,
                decision,
                now=now,
                change_idempotency_key=change_idempotency_key,
                change_record_url=change_record_url,
                vendor=vendor,
                severity=severity,
                package_ids=package_ids,
            )
        return summary, decision, state

    def rollback(
        self,
        controller: RolloutController,
        rollout_id: str,
        summary: StageHealthSummary,
        adapter: MockDeploymentAdapter,
        credential: OidcCredential,
        *,
        now: datetime,
        actor: str,
        critical_device_ids: Sequence[str],
        authorized: bool,
        observations: Sequence[HealthObservation] = (),
    ) -> tuple[MonitoringDecision, RolloutState]:
        """Execute rollback only after capability, policy and approval checks."""
        offered = decide_rollback(
            summary,
            adapter.capabilities(),
            update_kind=self._update_kind,
            critical_device_ids=critical_device_ids,
            authorized=authorized,
            actor=actor,
            now=now,
            config=self._config,
        )
        require_rollback_offered(offered)
        state = controller.state(rollout_id)
        current = state.stage_result(state.current_stage)
        if current.deployment_id is None:
            raise RollbackDenied("no deployment_id is bound to this stage")
        before, after = _versions(observations)
        try:
            result = adapter.rollback_or_uninstall(
                current.deployment_id, credential=credential, now=now
            )
        except PartialFailure as exc:
            decision = _with_outcome(
                offered,
                DecisionAction.ROLLBACK_PARTIAL,
                (*offered.reason_codes, "ROLLBACK_PARTIAL"),
                "partial_failure",
                before,
                after,
            )
            self.decisions.append(decision)
            raise PartialFailure(str(exc)) from exc
        except RollbackUnsupported:
            decision = _with_outcome(
                offered,
                DecisionAction.ROLLBACK_DENIED,
                (*offered.reason_codes, "ROLLBACK_UNSUPPORTED"),
                "unsupported",
                before,
                after,
            )
            self.decisions.append(decision)
            raise
        del result
        decision = _with_outcome(
            offered,
            DecisionAction.ROLLBACK_EXECUTED,
            offered.reason_codes,
            "succeeded",
            before,
            after,
        )
        self.decisions.append(decision)
        return decision, state

    def resume(
        self,
        controller: RolloutController,
        rollout_id: str,
        observations: Sequence[HealthObservation],
        adapter: MockDeploymentAdapter,
        credential: OidcCredential,
        *,
        now: datetime,
        actor: str,
    ) -> tuple[StageHealthSummary, MonitoringDecision, RolloutState]:
        """Resume only after a healthy, complete recovery window."""
        state = controller.state(rollout_id)
        plan = controller.plan_for(rollout_id)
        spec = plan.stage(state.current_stage)
        summary = evaluate_stage(
            observations,
            rollout_id=rollout_id,
            stage=state.current_stage,
            member_ids=spec.member_device_ids,
            now=now,
            update_kind=self._update_kind,
            clinical_criticality=self._clinical,
            config=self._config,
        )
        assert_resume_ready(summary, now=now)
        state = controller.resume(rollout_id, now=now, adapter=adapter, credential=credential)
        state = controller.record_health(rollout_id, to_signals(summary), now=now)
        decision = MonitoringDecision(
            decision_id=summary.summary_id,
            action=DecisionAction.RESUME_READY,
            reason_codes=summary.reason_codes,
            evidence_ids=(summary.summary_id,),
            actor=actor,
            at=now,
            rollback_outcome=None,
            before_versions=_versions(observations)[0],
            after_versions=_versions(observations)[1],
        )
        self.decisions.append(decision)
        return summary, decision, state

    def promote(
        self,
        controller: RolloutController,
        rollout_id: str,
        summary: StageHealthSummary,
        *,
        now: datetime,
        actor: str,
        reason: str,
        adapter: MockDeploymentAdapter,
        credential: OidcCredential,
        evidence: AuthorizationEvidence,
        package: PackageIdentity,
        environment_approved: bool,
    ) -> RolloutState:
        """Promote only when monitoring and the rollout controller both agree."""
        assert_promote_ready(summary, now=now)
        return controller.promote(
            rollout_id,
            actor=actor,
            reason=reason,
            now=now,
            adapter=adapter,
            credential=credential,
            evidence=evidence,
            package=package,
            environment_approved=environment_approved,
        )

    def _notify(
        self,
        summary: StageHealthSummary,
        decision: MonitoringDecision,
        *,
        now: datetime,
        change_idempotency_key: str,
        change_record_url: str,
        vendor: str,
        severity: str,
        package_ids: tuple[str, ...],
    ) -> None:
        if self._notifications is None:
            return
        event = build_monitoring_event(
            summary,
            decision,
            now=now,
            policy=self._policy,
            change_record_url=change_record_url,
            change_idempotency_key=change_idempotency_key,
            vendor=vendor,
            severity=severity,
            package_ids=package_ids,
        )
        self.alerts.append(self._notifications.publish(event))


def _versions(
    observations: Sequence[HealthObservation],
) -> tuple[tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]]:
    before: dict[str, str] = {}
    after: dict[str, str] = {}
    for item in observations:
        before[item.device_id] = item.before_version
        after[item.device_id] = item.after_version
    return tuple(before.items()), tuple(after.items())


def _with_outcome(
    offered: MonitoringDecision,
    action: DecisionAction,
    codes: tuple[str, ...],
    outcome: str,
    before: tuple[tuple[str, str], ...],
    after: tuple[tuple[str, str], ...],
) -> MonitoringDecision:
    return MonitoringDecision(
        decision_id=offered.decision_id,
        action=action,
        reason_codes=tuple(dict.fromkeys(codes)),
        evidence_ids=offered.evidence_ids,
        actor=offered.actor,
        at=offered.at,
        rollback_outcome=outcome,
        before_versions=before,
        after_versions=after,
    )
