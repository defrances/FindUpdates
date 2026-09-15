from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from findupdates.deployment import (
    AuthorizationEvidence,
    ErrorCode,
    MockDeploymentAdapter,
    OidcCredential,
    PackageIdentity,
    UpdateKind,
)
from findupdates.rollout import (
    STAGE_ORDER,
    ConcurrentRollout,
    EmergencyOverride,
    HealthSignals,
    RolloutController,
    RolloutDenied,
    RolloutStatus,
    StageStatus,
    build_plan,
    dict_to_plan,
    dict_to_state,
    in_maintenance_window,
    plan_to_dict,
    state_to_dict,
    synthetic_fleet,
)
from findupdates.rollout.simulate import NIGHTLY, synthetic_device

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAN_SCHEMA = REPO_ROOT / "schemas" / "rollout-plan" / "v1.schema.json"
STATE_SCHEMA = REPO_ROOT / "schemas" / "rollout-state" / "v1.schema.json"
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


def _healthy(members: int) -> HealthSignals:
    return HealthSignals(
        observed=True,
        success_count=members,
        failure_count=0,
        crash_count=0,
        connectivity_loss=0,
        validation_regressions=0,
        inconclusive_critical=0,
    )


def _plan(devices, **overrides):
    kwargs = {
        "package_id": PACKAGE.package_id,
        "package_sha256": PACKAGE.sha256,
        "change_idempotency_key": "change_abc",
        "policy_result": "REQUIRE_APPROVAL",
        "now": NOW,
        "observation_overrides": ZERO_WINDOWS,
    }
    kwargs.update(overrides)
    return build_plan(devices, **kwargs)


def _advance(controller, state, plan, adapter, *, now=NOW, approved=True, reason="criteria passed"):
    spec = plan.stage(state.current_stage)
    controller.record_health(state.rollout_id, _healthy(len(spec.member_device_ids)), now=now)
    return controller.promote(
        state.rollout_id,
        actor="rollout-operator",
        reason=reason,
        now=now,
        adapter=adapter,
        credential=_credential(),
        evidence=_evidence(),
        package=PACKAGE,
        environment_approved=approved,
    )


class StagedRolloutTests(unittest.TestCase):
    def test_success_path_lab_to_production(self) -> None:
        devices = synthetic_fleet()
        plan = _plan(devices)
        self.assertEqual([item.name for item in plan.stages], list(STAGE_ORDER))
        self.assertTrue(plan.stage("lab").member_device_ids)
        self.assertTrue(plan.stage("canary").member_device_ids)
        self.assertNotIn("crit-00", plan.stage("canary").member_device_ids)
        self.assertNotIn("crit-00", plan.stage("ring-1").member_device_ids)
        self.assertIn("crit-00", plan.stage("production").member_device_ids)
        errors = list(_validator(PLAN_SCHEMA).iter_errors(plan_to_dict(plan)))
        self.assertEqual([], errors)

        adapter = MockDeploymentAdapter()
        controller = RolloutController(devices)
        state = controller.start(
            plan,
            actor="lab-tech",
            reason="lab cohort authorized",
            now=NOW,
            adapter=adapter,
            credential=_credential(),
            evidence=_evidence(),
            package=PACKAGE,
        )
        self.assertEqual(state.current_stage, "lab")
        while state.status is not RolloutStatus.SUCCEEDED:
            state = _advance(
                controller,
                state,
                plan,
                adapter,
                reason=f"promote from {state.current_stage}",
            )
        self.assertIs(state.status, RolloutStatus.SUCCEEDED)
        self.assertEqual(
            [item.to_stage for item in state.promotions],
            ["canary", "ring-1", "ring-2", "production"],
        )
        self.assertTrue(all(item.actor == "rollout-operator" for item in state.promotions))
        self.assertTrue(all(item.membership_hash for item in state.promotions))
        errors = list(_validator(STATE_SCHEMA).iter_errors(state_to_dict(state)))
        self.assertEqual([], errors)
        blob = json.dumps(state_to_dict(state))
        self.assertNotIn("patient", blob.lower())
        self.assertNotIn("oidc-short-lived-token", blob)

    def test_failure_threshold_pauses_promotion(self) -> None:
        devices = synthetic_fleet()
        plan = _plan(devices)
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
        paused = controller.record_health(
            state.rollout_id,
            HealthSignals(True, 1, 1, 0, 0, 0, 0),
            now=NOW,
        )
        self.assertIs(paused.status, RolloutStatus.PAUSED)
        with self.assertRaises(RolloutDenied):
            controller.promote(
                paused.rollout_id,
                actor="rollout-operator",
                reason="should not promote",
                now=NOW,
                adapter=adapter,
                credential=_credential(),
                evidence=_evidence(),
                package=PACKAGE,
                environment_approved=True,
            )

    def test_inconclusive_critical_signal_is_conservative(self) -> None:
        devices = synthetic_fleet()
        plan = _plan(devices)
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
        paused = controller.record_health(
            state.rollout_id,
            HealthSignals(True, 2, 0, 0, 0, 0, 1),
            now=NOW,
        )
        self.assertIs(paused.status, RolloutStatus.PAUSED)
        self.assertIs(paused.stage_result("lab").status, StageStatus.PAUSED)

    def test_missing_health_and_incomplete_observation_block_promotion(self) -> None:
        devices = synthetic_fleet()
        plan = _plan(devices, observation_overrides={"lab": 60})
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
        with self.assertRaises(RolloutDenied):
            controller.promote(
                state.rollout_id,
                actor="rollout-operator",
                reason="no health",
                now=NOW,
                adapter=adapter,
                credential=_credential(),
                evidence=_evidence(),
                package=PACKAGE,
                environment_approved=True,
            )
        controller.record_health(state.rollout_id, _healthy(2), now=NOW)
        with self.assertRaises(RolloutDenied):
            controller.promote(
                state.rollout_id,
                actor="rollout-operator",
                reason="window open",
                now=NOW,
                adapter=adapter,
                credential=_credential(),
                evidence=_evidence(),
                package=PACKAGE,
                environment_approved=True,
            )
        promoted = controller.promote(
            state.rollout_id,
            actor="rollout-operator",
            reason="window complete",
            now=NOW + timedelta(minutes=61),
            adapter=adapter,
            credential=_credential(now=NOW + timedelta(minutes=61)),
            evidence=_evidence(),
            package=PACKAGE,
            environment_approved=True,
        )
        self.assertEqual(promoted.current_stage, "canary")

    def test_maintenance_window_is_respected(self) -> None:
        devices = synthetic_fleet(maintenance=NIGHTLY)
        self.assertFalse(in_maintenance_window(NOW, NIGHTLY))
        plan = _plan(devices)
        adapter = MockDeploymentAdapter()
        controller = RolloutController(devices)
        state = controller.start(
            plan,
            actor="lab-tech",
            reason="lab does not require a window",
            now=NOW,
            adapter=adapter,
            credential=_credential(),
            evidence=_evidence(),
            package=PACKAGE,
        )
        controller.record_health(state.rollout_id, _healthy(2), now=NOW)
        with self.assertRaises(RolloutDenied):
            controller.promote(
                state.rollout_id,
                actor="rollout-operator",
                reason="outside window",
                now=NOW,
                adapter=adapter,
                credential=_credential(),
                evidence=_evidence(),
                package=PACKAGE,
                environment_approved=True,
            )
        sunday = datetime(2026, 9, 20, 2, 30, tzinfo=UTC)
        self.assertTrue(in_maintenance_window(sunday, NIGHTLY))
        opened = controller.promote(
            state.rollout_id,
            actor="rollout-operator",
            reason="inside window",
            now=sunday,
            adapter=adapter,
            credential=_credential(now=sunday),
            evidence=_evidence(),
            package=PACKAGE,
            environment_approved=True,
        )
        self.assertEqual(opened.current_stage, "canary")

    def test_emergency_override_allows_closed_window(self) -> None:
        devices = synthetic_fleet(maintenance=NIGHTLY)
        plan = _plan(
            devices,
            emergency=EmergencyOverride(True, "on-call", "authorized emergency process"),
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
        controller.record_health(state.rollout_id, _healthy(2), now=NOW)
        opened = controller.promote(
            state.rollout_id,
            actor="on-call",
            reason="emergency process",
            now=NOW,
            adapter=adapter,
            credential=_credential(),
            evidence=_evidence(),
            package=PACKAGE,
            environment_approved=True,
        )
        self.assertEqual(opened.current_stage, "canary")

    def test_production_requires_explicit_approval(self) -> None:
        devices = synthetic_fleet()
        plan = _plan(devices)
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
        while state.current_stage != "ring-1" or state.status is RolloutStatus.SUCCEEDED:
            if state.status is RolloutStatus.SUCCEEDED:
                self.fail("reached success before ring-2 approval check")
            if state.current_stage == "ring-1" and state.stage_result("ring-1").health:
                break
            state = _advance(controller, state, plan, adapter)
        if state.stage_result("ring-1").health is None:
            state = controller.record_health(
                state.rollout_id,
                _healthy(len(plan.stage("ring-1").member_device_ids)),
                now=NOW,
            )
        with self.assertRaises(RolloutDenied):
            controller.promote(
                state.rollout_id,
                actor="rollout-operator",
                reason="no production approval",
                now=NOW,
                adapter=adapter,
                credential=_credential(),
                evidence=_evidence(),
                package=PACKAGE,
                environment_approved=False,
            )
        approved = controller.promote(
            state.rollout_id,
            actor="rollout-operator",
            reason="environment approved",
            now=NOW,
            adapter=adapter,
            credential=_credential(),
            evidence=_evidence(),
            package=PACKAGE,
            environment_approved=True,
        )
        self.assertEqual(approved.current_stage, "ring-2")

    def test_state_is_resumable_after_restart(self) -> None:
        devices = synthetic_fleet()
        plan = _plan(devices)
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
        controller.record_health(state.rollout_id, _healthy(2), now=NOW)
        snapshot = state_to_dict(controller.state(state.rollout_id))
        restored = RolloutController(devices)
        restored.restore(dict_to_plan(plan_to_dict(plan)), dict_to_state(snapshot))
        resumed = restored.promote(
            state.rollout_id,
            actor="rollout-operator",
            reason="workflow restarted",
            now=NOW,
            adapter=adapter,
            credential=_credential(),
            evidence=_evidence(),
            package=PACKAGE,
            environment_approved=True,
        )
        self.assertEqual(resumed.current_stage, "canary")
        again = restored.start(
            plan,
            actor="lab-tech",
            reason="duplicate start",
            now=NOW,
            adapter=adapter,
            credential=_credential(),
            evidence=_evidence(),
            package=PACKAGE,
        )
        self.assertEqual(again.rollout_id, resumed.rollout_id)

    def test_concurrent_rollout_is_rejected(self) -> None:
        devices = synthetic_fleet()
        plan_a = _plan(devices)
        plan_b = _plan(devices, change_idempotency_key="change_other")
        adapter = MockDeploymentAdapter()
        controller = RolloutController(devices)
        controller.start(
            plan_a,
            actor="lab-tech",
            reason="first",
            now=NOW,
            adapter=adapter,
            credential=_credential(),
            evidence=_evidence(),
            package=PACKAGE,
        )
        with self.assertRaises(ConcurrentRollout):
            controller.start(
                plan_b,
                actor="lab-tech",
                reason="second",
                now=NOW,
                adapter=adapter,
                credential=_credential(),
                evidence=_evidence(),
                package=PACKAGE,
            )

    def test_partial_backend_failure_does_not_promote(self) -> None:
        devices = synthetic_fleet()
        plan = _plan(devices)
        adapter = MockDeploymentAdapter(inject_error=ErrorCode.PARTIAL_FAILURE)
        controller = RolloutController(devices)
        paused = controller.start(
            plan,
            actor="lab-tech",
            reason="start",
            now=NOW,
            adapter=adapter,
            credential=_credential(),
            evidence=_evidence(),
            package=PACKAGE,
        )
        self.assertIs(paused.status, RolloutStatus.PAUSED)
        self.assertIs(paused.stage_result("lab").status, StageStatus.FAILED)
        with self.assertRaises(RolloutDenied):
            controller.promote(
                paused.rollout_id,
                actor="rollout-operator",
                reason="partial failure",
                now=NOW,
                adapter=adapter,
                credential=_credential(),
                evidence=_evidence(),
                package=PACKAGE,
                environment_approved=True,
            )

    def test_hold_policy_cannot_build_plan(self) -> None:
        with self.assertRaises(ValueError):
            _plan(synthetic_fleet(), policy_result="HOLD")

    def test_critical_device_cannot_join_canary(self) -> None:
        devices = (
            synthetic_device("lab-00", group="lab-ring-0", site="lab"),
            synthetic_device("crit-00", criticality="critical"),
        )
        with self.assertRaises(RolloutDenied):
            _plan(
                devices,
                explicit={"lab": ("lab-00",), "canary": ("crit-00",)},
            )


if __name__ == "__main__":
    unittest.main()
