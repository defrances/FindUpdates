"""Detect pipeline: fixtures, bounded AI, notifications. No live vendors."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from findupdates.mvp.fixtures import NOW
from findupdates.pipeline.__main__ import main
from findupdates.pipeline.detect import DetectOptions, detect_updates
from findupdates.risk.models import PolicyResult


class PipelineDetectTests(unittest.TestCase):
    def test_fixture_detect_analyzes_and_notifies(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            run = detect_updates(
                DetectOptions(output_dir=root),
                now=NOW,
            )
            summary = json.loads((root / "assess" / "summary.json").read_text(encoding="utf-8"))
            report = (root / "report.md").read_text(encoding="utf-8")
            analyses = list((root / "assess" / "analysis").glob("*.json"))
            notices = list((root / "assess" / "notifications").glob("*.json"))
            payload = json.loads(analyses[0].read_text(encoding="utf-8"))
        self.assertEqual(run.exit_code, 0)
        self.assertEqual(run.source, "fixtures")
        policies = {item["advisory_id"]: item["policy_result"] for item in summary["changes"]}
        self.assertIn(PolicyResult.REQUIRE_APPROVAL.value, policies.values())
        self.assertIn(PolicyResult.BLOCK.value, policies.values())
        self.assertTrue(all(item["analyzed"] for item in summary["changes"]))
        self.assertTrue(all(item["notified"] for item in summary["changes"]))
        self.assertGreaterEqual(len(analyses), 2)
        self.assertGreaterEqual(len(notices), 1)
        self.assertNotIn("token", payload)
        self.assertIn("FindUpdates detect", report)
        self.assertIn("Bounded AI", report)
        self.assertIn("Notifications", report)
        self.assertNotIn("token", report.lower())

    def test_cli_detect_fixtures_does_not_require_keys(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            code = main(["detect", "--source", "fixtures", "--output-dir", str(root)], environ={})
            report = (root / "report.md").read_text(encoding="utf-8")
        self.assertEqual(code, 0)
        self.assertIn("FindUpdates detect", report)
        self.assertIn("Bounded AI", report)
        self.assertIn("Notifications", report)


if __name__ == "__main__":
    unittest.main()
