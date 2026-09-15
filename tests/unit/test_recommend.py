"""Per-station recommendations. Official URLs only; no deploy authorization."""

from __future__ import annotations

import unittest

from findupdates.applicability import evaluate
from findupdates.inventory import load_synthetic_workstations, refresh_for_assessment
from findupdates.mvp.fixtures import NOW, microsoft_advisory
from findupdates.pipeline.recommend import (
    CANDIDATE,
    official_advisory_url,
    recommend_station,
    render_station_report,
)
from findupdates.risk import assess as assess_risk


class OfficialUrlTests(unittest.TestCase):
    def test_microsoft_cve_uses_msrc_update_guide(self) -> None:
        url = official_advisory_url(microsoft_advisory())
        self.assertEqual(
            url, "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12345"
        )


class StationRecommendationTests(unittest.TestCase):
    def test_kb_is_candidate_on_ct_console_with_official_link(self) -> None:
        advisory = microsoft_advisory()
        device = next(
            item
            for item in load_synthetic_workstations()
            if item.device_id == "SYNTHETIC-CT-IMG-01"
        )
        device = refresh_for_assessment(device, NOW)
        app = evaluate(advisory, device, now=NOW)
        risk = assess_risk(advisory, device, app, now=NOW)
        row = recommend_station(advisory, device, app, risk)
        self.assertEqual(row.action, CANDIDATE)
        self.assertEqual(row.package, "KB5060001")
        self.assertEqual(
            row.official_url,
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12345",
        )
        self.assertIn("does not authorize installation", row.explanation)
        markdown = render_station_report((row,), correlation_id="assess-test")
        self.assertIn("SYNTHETIC-CT-IMG-01", markdown)
        self.assertIn("KB5060001", markdown)
        self.assertIn("msrc.microsoft.com", markdown)
        self.assertNotIn("token", markdown.lower())


if __name__ == "__main__":
    unittest.main()
