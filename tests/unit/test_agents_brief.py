"""Run-level Agentic AI briefing. No live model and no deployment."""

from __future__ import annotations

import unittest

from findupdates.agents import BriefSource, OfflineProvider, analyze, brief_updates
from findupdates.applicability import evaluate
from findupdates.config import Settings
from findupdates.mvp.fixtures import NOW, imaging_workstation, microsoft_advisory
from findupdates.risk import assess as assess_risk


class UpdateBriefingTests(unittest.TestCase):
    def test_briefing_echoes_policy_and_refuses_empty_sources(self) -> None:
        advisory = microsoft_advisory()
        device = imaging_workstation()
        app = evaluate(advisory, device, now=NOW)
        risk = assess_risk(advisory, device, app, now=NOW)
        analysis = analyze(
            advisory,
            device,
            app,
            risk,
            now=NOW,
            provider=OfflineProvider(),
            settings=Settings(ai_enabled=True, ai_provider="offline"),
        )
        source = BriefSource(
            title=advisory.title,
            deployment_group=device.deployment_group,
            analysis=analysis,
        )
        briefing = brief_updates(
            (source,),
            correlation_id="assess-test",
            now=NOW,
        )
        self.assertIn("Agentic AI analysis of updates", briefing.markdown)
        self.assertIn(advisory.advisory_id, briefing.markdown)
        self.assertIn(f"policy=`{risk.policy_result.value}`", briefing.markdown)
        self.assertIn("Human approval is required", briefing.markdown)
        self.assertFalse(briefing.used_fallback)
        with self.assertRaises(ValueError):
            brief_updates((), correlation_id="assess-test", now=NOW)


if __name__ == "__main__":
    unittest.main()
