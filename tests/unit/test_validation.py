from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from findupdates.changerecords.models import PromotionDenied
from findupdates.validation import (
    TestOutcome,
    assert_validation_gate,
    default_imaging_target,
    load_profile_for_model,
    plan_to_dict,
    result_to_dict,
    run_validation,
)
from findupdates.validation.workflow import main as validation_main

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAN_SCHEMA = REPO_ROOT / "schemas" / "validation-plan" / "v1.schema.json"
RESULT_SCHEMA = REPO_ROOT / "schemas" / "validation-result" / "v1.schema.json"
NOW = datetime(2026, 9, 15, 12, tzinfo=UTC)


def _validator(path: Path) -> Draft202012Validator:
    return Draft202012Validator(
        json.loads(path.read_text(encoding="utf-8")),
        format_checker=FormatChecker(),
    )


class ValidationLabTests(unittest.TestCase):
    def test_profile_matches_device_model_and_plan_schema(self) -> None:
        plan = load_profile_for_model("ImagingStation-X200")
        self.assertEqual(plan.device_model, "ImagingStation-X200")
        self.assertTrue(any(item.clinical and item.mandatory for item in plan.cases))
        errors = list(_validator(PLAN_SCHEMA).iter_errors(plan_to_dict(plan)))
        self.assertEqual([], errors)

    def test_signed_off_lab_run_produces_pass_evidence(self) -> None:
        plan = load_profile_for_model("ImagingStation-X200")
        target = default_imaging_target()
        result = run_validation(plan, target, now=NOW, human_sign_off=frozenset({"known_issues"}))
        self.assertIs(result.overall, TestOutcome.PASS)
        self.assertFalse(result.blocks_promotion)
        self.assertNotEqual(result.baseline.os_version, result.after.os_version)
        self.assertEqual(len(result.artifacts), 3)
        errors = list(_validator(RESULT_SCHEMA).iter_errors(result_to_dict(result)))
        self.assertEqual([], errors)
        assert_validation_gate(result, "production")

    def test_failing_clinical_smoke_blocks_promotion(self) -> None:
        plan = load_profile_for_model("ImagingStation-X200")
        target = default_imaging_target(fail_case_ids=frozenset({"medical_app_smoke"}))
        result = run_validation(plan, target, now=NOW, human_sign_off=frozenset({"known_issues"}))
        smoke = next(item for item in result.cases if item.case_id == "medical_app_smoke")
        os_health = next(item for item in result.cases if item.case_id == "os_health")
        self.assertIs(os_health.outcome, TestOutcome.PASS)
        self.assertIs(smoke.outcome, TestOutcome.FAIL)
        self.assertTrue(smoke.clinical)
        self.assertIs(result.overall, TestOutcome.FAIL)
        self.assertTrue(result.blocks_promotion)
        with self.assertRaises(PromotionDenied):
            assert_validation_gate(result, "canary")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "result.json"
            path.write_text(json.dumps(result_to_dict(result)), encoding="utf-8")
            self.assertEqual(validation_main([str(path), "production"]), 1)
            self.assertEqual(validation_main([str(path), "lab"]), 0)

    def test_inconclusive_required_clinical_is_not_pass(self) -> None:
        plan = load_profile_for_model("ImagingStation-X200")
        result = run_validation(plan, default_imaging_target(), now=NOW)
        known = next(item for item in result.cases if item.case_id == "known_issues")
        self.assertIs(known.outcome, TestOutcome.INCONCLUSIVE)
        self.assertTrue(known.mandatory)
        self.assertTrue(known.clinical)
        self.assertIs(result.overall, TestOutcome.INCONCLUSIVE)
        self.assertTrue(result.blocks_promotion)

    def test_payload_has_no_patient_data(self) -> None:
        plan = load_profile_for_model("ImagingStation-X200")
        result = run_validation(
            plan,
            default_imaging_target(),
            now=NOW,
            human_sign_off=frozenset({"known_issues"}),
        )
        blob = json.dumps(result_to_dict(result))
        self.assertNotIn("patient", blob.lower())
        self.assertNotIn("mrn", blob.lower())


if __name__ == "__main__":
    unittest.main()
