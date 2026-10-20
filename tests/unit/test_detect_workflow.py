"""Detect workflow handshake: manual run and Orchestrator dispatch."""

from __future__ import annotations

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DETECT_YML = REPO_ROOT / ".github" / "workflows" / "detect.yml"
COLLECT_YML = REPO_ROOT / ".github" / "workflows" / "collect.yml"


class DetectWorkflowTests(unittest.TestCase):
    def test_manual_detect_notifies_orchestrator_without_issue_payload(self) -> None:
        text = DETECT_YML.read_text(encoding="utf-8")
        self.assertNotIn("schedule:", text)
        self.assertNotIn("cron:", text)
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("github.event.inputs.source || 'live'", text)
        self.assertIn("findupdates-complete", text)
        self.assertIn("findupdates-report-json", text)
        self.assertIn("Notify Orchestrator", text)
        self.assertIn("secrets.ORCHESTRATOR_PAT", text)
        self.assertNotIn("gh issue create", text)
        self.assertNotIn("desktop-application-merged", text)

    def test_collect_is_manual_only(self) -> None:
        text = COLLECT_YML.read_text(encoding="utf-8")
        self.assertNotIn("schedule:", text)
        self.assertNotIn("cron:", text)
        self.assertIn("workflow_dispatch:", text)


if __name__ == "__main__":
    unittest.main()
