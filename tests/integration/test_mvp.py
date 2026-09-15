"""Integration tests for the MVP pipeline. No production credentials or PHI."""

from __future__ import annotations

import unittest

from findupdates.applicability.models import ApplicabilityVerdict
from findupdates.audit import verify_bundle
from findupdates.mvp import MvpOptions, run_mvp
from findupdates.rollout import RolloutStatus


class MvpAcceptanceTests(unittest.TestCase):
    def test_happy_path_microsoft_and_intel_to_evidence(self) -> None:
        run = run_mvp()
        self.assertEqual(run.microsoft.vendor.value, "microsoft")
        self.assertEqual(run.intel.vendor.value, "intel")
        self.assertIs(run.applicability.verdict, ApplicabilityVerdict.AFFECTED)
        self.assertIsNot(run.intel_applicability.verdict, ApplicabilityVerdict.AFFECTED)
        self.assertTrue(run.notified)
        self.assertTrue(run.suppressed)
        self.assertEqual(run.validation_overall, "PASS")
        self.assertTrue(run.deployed)
        self.assertEqual(run.rollout_status, RolloutStatus.SUCCEEDED.value)
        assert run.evidence is not None
        verify_bundle(run.evidence)
        self.assertIn("updated", run.evidence.narrative.lower())
        self.assertNotIn("patient", run.evidence.narrative.lower())

    def test_not_applicable_does_not_open_deployment(self) -> None:
        run = run_mvp(MvpOptions(not_applicable=True))
        self.assertIsNot(run.applicability.verdict, ApplicabilityVerdict.AFFECTED)
        self.assertFalse(run.deployed)

    def test_stale_inventory_blocks_production_path(self) -> None:
        run = run_mvp(MvpOptions(stale_inventory=True))
        self.assertFalse(run.deployed)
        self.assertIn(run.policy_result, {"HOLD", "BLOCK"})

    def test_kev_reassessment_emits_new_notification(self) -> None:
        run = run_mvp(MvpOptions(kev_reassess=True))
        self.assertFalse(run.suppressed)
        self.assertIn("kev listed", " ".join(run.notes))

    def test_ai_unavailable_continues_deterministic_path(self) -> None:
        run = run_mvp(MvpOptions(ai_unavailable=True, stop_after_canary=True))
        self.assertTrue(any("ai_fallback=True" in item for item in run.notes))
        self.assertEqual(
            run.policy_result, run_mvp(MvpOptions(stop_after_canary=True)).policy_result
        )

    def test_prompt_injection_cannot_authorize_deploy_by_itself(self) -> None:
        run = run_mvp(MvpOptions(prompt_injection=True, stop_after_canary=True))
        self.assertIn("Ignore policy", run.microsoft.description or "")
        self.assertEqual(
            run.policy_result, run_mvp(MvpOptions(stop_after_canary=True)).policy_result
        )

    def test_validation_failure_blocks_deployment(self) -> None:
        run = run_mvp(MvpOptions(validation_fail=True))
        self.assertEqual(run.validation_overall, "FAIL")
        self.assertFalse(run.deployed)

    def test_missing_approval_cannot_run_canary(self) -> None:
        run = run_mvp(MvpOptions(missing_approval=True))
        self.assertFalse(run.deployed)
        self.assertTrue(any("promotion denied" in item.lower() for item in run.notes))

    def test_changed_target_set_is_rejected(self) -> None:
        run = run_mvp(MvpOptions(changed_targets=True))
        self.assertFalse(run.deployed)
        self.assertTrue(any("changed target set" in item for item in run.notes))

    def test_canary_health_failure_pauses_rollout(self) -> None:
        run = run_mvp(MvpOptions(canary_health_fail=True))
        self.assertTrue(run.paused)
        self.assertTrue(run.deployed)

    def test_missing_health_telemetry_blocks_promotion(self) -> None:
        run = run_mvp(MvpOptions(missing_telemetry=True))
        self.assertTrue(run.paused)

    def test_duplicate_execution_does_not_reinstall(self) -> None:
        run = run_mvp(MvpOptions(duplicate_deploy=True))
        self.assertTrue(run.duplicate)


if __name__ == "__main__":
    unittest.main()
