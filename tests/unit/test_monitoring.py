from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from findupdates.deployment import (
    OEM_CAPABILITIES,
    AuthorizationEvidence,
    DeploymentStatus,
    ErrorCode,
    MockDeploymentAdapter,
    OidcCredential,
    PackageIdentity,
    UpdateKind,
)
from findupdates.deployment.errors import PartialFailure
from findupdates.monitoring import (
    DecisionAction,
    HealthState,
    PostDeployMonitor,
    PromotionBlocked,
    ResumeDenied,
    RollbackDenied,
    evaluate_stage,
    load_monitoring_config,
    observation_to_dict,
    simulate_app_crash_spike,
    simulate_boot_failure,
    simulate_connectivity_loss,
    simulate_healthy,
    simulate_missing_telemetry,
    simulate_stale_heartbeat,
    summary_to_dict,
)
from findupdates.monitoring.config import observation_window_minutes
from findupdates.monitoring.decide import decide_rollback
from findupdates.notifications import MemoryChannel, NotificationService
from findupdates.rollout import (
    STAGE_ORDER,
    RolloutController,
    RolloutDenied,
    RolloutStatus,
    build_plan,
    synthetic_fleet,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
OBS_SCHEMA = REPO_ROOT / "schemas" / "health-observation" / "v1.schema.json"
SUM_SCHEMA = REPO_ROOT / "schemas" / "stage-health-summary" / "v1.schema.json"
NOW = datetime(2026, 9, 15, 18, tzinfo=UTC)
PACKAGE = PackageIdentity(
    kind=UpdateKind.OS,
    package_id="KB5048685",
    version="10.0.19045.5011",
    sha256="ab" * 32,
)
ZERO_WINDOWS = dict.fromkeys(STAGE_ORDER, 0)


def _validator(path: Path) -> Draft202012Validator:
    return Draft202012Validator(
        json.loads(path.read_text(encoding="utf-8")),
        format_checker=FormatChecker(),
    )


def _zero_monitoring() -> dict[str, object]:
    config = load_monitoring_config()
    config["windows_minutes"] = {key: 0 for key in config["windows_minutes"]}
    return config


def _evidence() -> AuthorizationEvidence:
    return AuthorizationEvidence(
        advisory_ids=("advisory-msrc-1",),
        risk_assessment_id="risk_abc",
        policy_result="REQUIRE_APPROVAL",
        change_idempotency_key="change_abc",
        validation_result_id="validation_abc",
        approver="security-approver",
        approved_at=NOW,
    )


def _credential(*, now: datetime = NOW) -> OidcCredential:
    return OidcCredential(
        audience="api://findupdates-deployment",
        expires_at=now + timedelta(hours=6),
        token="oidc-short-lived-token",
    )


def _start(monitor: PostDeployMonitor | None = None):
    devices = synthetic_fleet()
    plan = build_plan(
        devices,
        package_id=PACKAGE.package_id,
        package_sha256=PACKAGE.sha256,
        change_idempotency_key="change_abc",
        policy_result="REQUIRE_APPROVAL",
        now=NOW,
        observation_overrides=ZERO_WINDOWS,
    )
    adapter = MockDeploymentAdapter()
    controller = RolloutController(devices)
    state = controller.start(
        plan,
        actor="lab-tech",
        reason="start",
        now=NOW,
        adapter=adapter,
        credential=_credential(),
        evidence=_evidence(),
        package=PACKAGE,
    )
    watch = monitor or PostDeployMonitor(config=_zero_monitoring())
    return devices, plan, adapter, controller, watch, state


class PostDeployMonitoringTests(unittest.TestCase):
    def test_canary_degradation_pauses_next_ring(self) -> None:
        _devices, plan, adapter, controller, monitor, state = _start()
        members = plan.stage("lab").member_device_ids
        summary, decision, state = monitor.ingest(
            controller,
            state.rollout_id,
            simulate_healthy(members, stage="lab", now=NOW),
            now=NOW,
            actor="monitor",
        )
        self.assertFalse(summary.pause_rollout)
        state = monitor.promote(
            controller,
            state.rollout_id,
            summary,
            now=NOW,
            actor="operator",
            reason="lab healthy",
            adapter=adapter,
            credential=_credential(),
            evidence=_evidence(),
            package=PACKAGE,
            environment_approved=True,
        )
        self.assertEqual(state.current_stage, "canary")
        canary = plan.stage("canary").member_device_ids
        summary, decision, state = monitor.ingest(
            controller,
            state.rollout_id,
            simulate_boot_failure(canary, stage="canary", now=NOW),
            now=NOW,
            actor="monitor",
        )
        self.assertTrue(summary.pause_rollout)
        self.assertIs(summary.overall, HealthState.FAILED)
        self.assertIn("BOOT_FAILED", summary.reason_codes)
        self.assertIs(decision.action, DecisionAction.PAUSE)
        self.assertIs(state.status, RolloutStatus.PAUSED)
        with self.assertRaises(RolloutDenied):
            controller.promote(
                state.rollout_id,
                actor="operator",
                reason="should not advance",
                now=NOW,
                adapter=adapter,
                credential=_credential(),
                evidence=_evidence(),
                package=PACKAGE,
                environment_approved=True,
            )

    def test_healthy_stage_waits_for_observation_window(self) -> None:
        devices = synthetic_fleet()
        plan = build_plan(
            devices,
            package_id=PACKAGE.package_id,
            package_sha256=PACKAGE.sha256,
            change_idempotency_key="change_abc",
            policy_result="REQUIRE_APPROVAL",
            now=NOW,
            observation_overrides=ZERO_WINDOWS,
        )
        adapter = MockDeploymentAdapter()
        controller = RolloutController(devices)
        state = controller.start(
            plan,
            actor="lab-tech",
            reason="start",
            now=NOW,
            adapter=adapter,
            credential=_credential(),
            evidence=_evidence(),
            package=PACKAGE,
        )
        monitor = PostDeployMonitor()
        members = plan.stage("lab").member_device_ids
        summary, _decision, state = monitor.ingest(
            controller,
            state.rollout_id,
            simulate_healthy(members, stage="lab", now=NOW),
            now=NOW,
            actor="monitor",
        )
        self.assertGreater(summary.window_minutes, 0)
        with self.assertRaises(PromotionBlocked):
            monitor.promote(
                controller,
                state.rollout_id,
                summary,
                now=NOW,
                actor="operator",
                reason="too early",
                adapter=adapter,
                credential=_credential(),
                evidence=_evidence(),
                package=PACKAGE,
                environment_approved=True,
            )
        later = NOW + timedelta(minutes=summary.window_minutes)
        promoted = monitor.promote(
            controller,
            state.rollout_id,
            summary,
            now=later,
            actor="operator",
            reason="window complete",
            adapter=adapter,
            credential=_credential(now=later),
            evidence=_evidence(),
            package=PACKAGE,
            environment_approved=True,
        )
        self.assertEqual(promoted.current_stage, "canary")

    def test_missing_and_stale_telemetry_are_not_healthy(self) -> None:
        members = ("lab-00", "lab-01")
        missing = evaluate_stage(
            simulate_missing_telemetry(members, stage="lab", now=NOW),
            rollout_id="rollout_test",
            stage="lab",
            member_ids=members,
            now=NOW,
            update_kind="os",
            clinical_criticality="medium",
            config=_zero_monitoring(),
        )
        self.assertIs(missing.overall, HealthState.INCONCLUSIVE)
        self.assertTrue(missing.pause_rollout)
        self.assertIn("MISSING_TELEMETRY", missing.reason_codes)
        stale = evaluate_stage(
            simulate_stale_heartbeat(members, stage="lab", now=NOW),
            rollout_id="rollout_test",
            stage="lab",
            member_ids=members,
            now=NOW,
            update_kind="os",
            clinical_criticality="medium",
        )
        self.assertIs(stale.overall, HealthState.INCONCLUSIVE)
        self.assertIn("STALE_HEARTBEAT", stale.reason_codes)
        self.assertNotEqual(stale.overall, HealthState.HEALTHY)

    def test_crash_and_connectivity_pause(self) -> None:
        _devices, plan, adapter, controller, monitor, state = _start()
        members = plan.stage("lab").member_device_ids
        crashed, _decision, paused = monitor.ingest(
            controller,
            state.rollout_id,
            simulate_app_crash_spike(members, stage="lab", now=NOW),
            now=NOW,
            actor="monitor",
        )
        self.assertIn("APP_CRASH_SPIKE", crashed.reason_codes)
        self.assertIs(paused.status, RolloutStatus.PAUSED)
        devices2, plan2, adapter2, controller2, monitor2, state2 = _start()
        del devices2
        lost, _d2, paused2 = monitor2.ingest(
            controller2,
            state2.rollout_id,
            simulate_connectivity_loss(plan2.stage("lab").member_device_ids, stage="lab", now=NOW),
            now=NOW,
            actor="monitor",
        )
        self.assertIn("CONNECTIVITY_LOSS", lost.reason_codes)
        self.assertIs(paused2.status, RolloutStatus.PAUSED)
        del adapter, adapter2

    def test_rollback_requires_capability_and_critical_approval(self) -> None:
        _devices, plan, adapter, controller, monitor, state = _start()
        members = plan.stage("lab").member_device_ids
        summary, _decision, _state = monitor.ingest(
            controller,
            state.rollout_id,
            simulate_boot_failure(members, stage="lab", now=NOW),
            now=NOW,
            actor="monitor",
        )
        denied = decide_rollback(
            summary,
            OEM_CAPABILITIES,
            update_kind="os",
            critical_device_ids=(),
            authorized=False,
            actor="operator",
            now=NOW,
            config=_zero_monitoring(),
        )
        self.assertIs(denied.action, DecisionAction.ROLLBACK_DENIED)
        self.assertIn("ROLLBACK_UNSUPPORTED", denied.reason_codes)
        unapproved = decide_rollback(
            summary,
            adapter.capabilities(),
            update_kind="os",
            critical_device_ids=members,
            authorized=False,
            actor="operator",
            now=NOW,
            config=_zero_monitoring(),
        )
        self.assertIn("ROLLBACK_CRITICAL_UNAPPROVED", unapproved.reason_codes)
        with self.assertRaises(RollbackDenied):
            monitor.rollback(
                controller,
                state.rollout_id,
                summary,
                adapter,
                _credential(),
                now=NOW,
                actor="operator",
                critical_device_ids=members,
                authorized=False,
            )
        executed, _state = monitor.rollback(
            controller,
            state.rollout_id,
            summary,
            adapter,
            _credential(),
            now=NOW,
            actor="operator",
            critical_device_ids=members,
            authorized=True,
            observations=simulate_boot_failure(members, stage="lab", now=NOW),
        )
        self.assertIs(executed.action, DecisionAction.ROLLBACK_EXECUTED)
        self.assertEqual(executed.rollback_outcome, "succeeded")
        self.assertTrue(executed.before_versions)
        self.assertTrue(executed.after_versions)
        deployment_id = state.stage_result("lab").deployment_id
        self.assertIsNotNone(deployment_id)
        self.assertIs(adapter.status(deployment_id or "").status, DeploymentStatus.ROLLED_BACK)

    def test_partial_rollback_does_not_claim_success(self) -> None:
        devices = synthetic_fleet()
        plan = build_plan(
            devices,
            package_id=PACKAGE.package_id,
            package_sha256=PACKAGE.sha256,
            change_idempotency_key="change_abc",
            policy_result="REQUIRE_APPROVAL",
            now=NOW,
            observation_overrides=ZERO_WINDOWS,
        )
        adapter = MockDeploymentAdapter(inject_rollback_error=ErrorCode.PARTIAL_FAILURE)
        controller = RolloutController(devices)
        state = controller.start(
            plan,
            actor="lab-tech",
            reason="start",
            now=NOW,
            adapter=adapter,
            credential=_credential(),
            evidence=_evidence(),
            package=PACKAGE,
        )
        monitor = PostDeployMonitor(config=_zero_monitoring())
        members = plan.stage("lab").member_device_ids
        summary, _decision, state = monitor.ingest(
            controller,
            state.rollout_id,
            simulate_boot_failure(members, stage="lab", now=NOW),
            now=NOW,
            actor="monitor",
        )
        with self.assertRaises(PartialFailure):
            monitor.rollback(
                controller,
                state.rollout_id,
                summary,
                adapter,
                _credential(),
                now=NOW,
                actor="operator",
                critical_device_ids=(),
                authorized=True,
            )
        self.assertIs(monitor.decisions[-1].action, DecisionAction.ROLLBACK_PARTIAL)
        self.assertEqual(monitor.decisions[-1].rollback_outcome, "partial_failure")
        self.assertIs(controller.state(state.rollout_id).status, RolloutStatus.PAUSED)

    def test_resume_after_healthy_recovery(self) -> None:
        _devices, plan, adapter, controller, monitor, state = _start()
        members = plan.stage("lab").member_device_ids
        _summary, _decision, state = monitor.ingest(
            controller,
            state.rollout_id,
            simulate_boot_failure(members, stage="lab", now=NOW),
            now=NOW,
            actor="monitor",
        )
        with self.assertRaises(ResumeDenied):
            monitor.resume(
                controller,
                state.rollout_id,
                simulate_boot_failure(members, stage="lab", now=NOW),
                adapter,
                _credential(),
                now=NOW,
                actor="operator",
            )
        recovered, decision, state = monitor.resume(
            controller,
            state.rollout_id,
            simulate_healthy(members, stage="lab", now=NOW),
            adapter,
            _credential(),
            now=NOW,
            actor="operator",
        )
        self.assertIs(decision.action, DecisionAction.RESUME_READY)
        self.assertIs(recovered.overall, HealthState.HEALTHY)
        self.assertIs(state.status, RolloutStatus.IN_PROGRESS)

    def test_pause_notifies_operators(self) -> None:
        channel = MemoryChannel()
        service = NotificationService(channels={"github": channel})
        monitor = PostDeployMonitor(config=_zero_monitoring(), notifications=service)
        _devices, plan, _adapter, controller, _default, state = _start(monitor)
        del _default
        members = plan.stage("lab").member_device_ids
        _summary, decision, _state = monitor.ingest(
            controller,
            state.rollout_id,
            simulate_boot_failure(members, stage="lab", now=NOW),
            now=NOW,
            actor="monitor",
            package_ids=(PACKAGE.package_id,),
        )
        self.assertIs(decision.action, DecisionAction.PAUSE)
        self.assertEqual(len(monitor.alerts), 1)
        self.assertFalse(monitor.alerts[0].suppressed)
        self.assertEqual(len(channel.sent), 1)
        blob = channel.markdown[0].lower()
        self.assertNotIn("patient", blob)
        self.assertNotIn("mrn", blob)

    def test_schemas_and_firmware_window(self) -> None:
        obs = simulate_healthy(("lab-00",), stage="lab", now=NOW)[0]
        errors = list(_validator(OBS_SCHEMA).iter_errors(observation_to_dict(obs)))
        self.assertEqual([], errors)
        summary = evaluate_stage(
            simulate_healthy(("lab-00",), stage="lab", now=NOW),
            rollout_id="rollout_test",
            stage="lab",
            member_ids=("lab-00",),
            now=NOW,
            update_kind="os",
            clinical_criticality="medium",
            config=_zero_monitoring(),
        )
        errors = list(_validator(SUM_SCHEMA).iter_errors(summary_to_dict(summary)))
        self.assertEqual([], errors)
        config = load_monitoring_config()
        self.assertGreater(
            observation_window_minutes(
                config, update_kind="firmware", clinical_criticality="critical"
            ),
            observation_window_minutes(config, update_kind="os", clinical_criticality="medium"),
        )


if __name__ == "__main__":
    unittest.main()
