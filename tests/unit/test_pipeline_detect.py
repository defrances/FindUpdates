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
            analyses = [
                path
                for path in (root / "assess" / "analysis").glob("*.json")
                if path.name not in {"run.json"}
            ]
            notices = list((root / "assess" / "notifications").glob("*.json"))
            payload = json.loads(analyses[0].read_text(encoding="utf-8"))
            briefing = (root / "assess" / "analysis" / "updates.md").read_text(encoding="utf-8")
            run_json = json.loads(
                (root / "assess" / "analysis" / "run.json").read_text(encoding="utf-8")
            )
            recs = json.loads(
                (root / "assess" / "recommendations.json").read_text(encoding="utf-8")
            )
            rec_md = (root / "assess" / "recommendations.md").read_text(encoding="utf-8")
            rec_html = (root / "assess" / "recommendations.html").read_text(encoding="utf-8")
            report_html = (root / "report.html").read_text(encoding="utf-8")
        self.assertEqual(run.exit_code, 0)
        self.assertEqual(run.source, "fixtures")
        policies = {item["policy_result"] for item in summary["changes"]}
        self.assertIn(PolicyResult.REQUIRE_APPROVAL.value, policies)
        self.assertIn(PolicyResult.BLOCK.value, policies)
        self.assertTrue(all(item["analyzed"] for item in summary["changes"]))
        self.assertTrue(all(item["notified"] for item in summary["changes"]))
        self.assertGreaterEqual(len(analyses), 2)
        self.assertGreaterEqual(len(notices), 1)
        self.assertNotIn("token", payload)
        self.assertNotIn("token", run_json)
        self.assertEqual(run_json["item_count"], len(analyses))
        self.assertIn("FindUpdates detect", report)
        self.assertIn("Station update recommendations", report)
        self.assertIn("SYNTHETIC-CT-IMG-01", report)
        self.assertIn("candidate_for_validation", report)
        self.assertIn("KB5060001", report)
        self.assertIn(
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12345",
            report,
        )
        self.assertIn("Station update recommendations", rec_md)
        self.assertIn('<html lang="en">', rec_html)
        self.assertIn("Candidate for validation", rec_html)
        self.assertEqual(rec_html, report_html)
        self.assertIn("report.html", report)
        self.assertNotIn("token", recs)
        listed_actions = {item["action"] for item in recs["items"]}
        self.assertIn("candidate_for_validation", listed_actions)
        self.assertIn("Agentic AI analysis of updates", briefing)
        self.assertNotIn("token", report.lower())

    def test_cli_detect_fixtures_does_not_require_keys(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            code = main(["detect", "--source", "fixtures", "--output-dir", str(root)], environ={})
            report = (root / "report.md").read_text(encoding="utf-8")
        self.assertEqual(code, 0)
        self.assertIn("FindUpdates detect", report)
        self.assertIn("Station update recommendations", report)
        self.assertIn("KB5060001", report)


if __name__ == "__main__":
    unittest.main()
