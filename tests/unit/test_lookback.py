"""Lookback window: last week of dated updates, not a historical dump."""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from findupdates.collectors.lookback import advisory_in_lookback, in_lookback, window_start
from findupdates.config import Settings
from findupdates.mvp.fixtures import microsoft_advisory


class LookbackWindowTests(unittest.TestCase):
    def test_defaults_are_seven_days(self) -> None:
        settings = Settings()
        self.assertEqual(settings.msrc_lookback_days, 7)
        self.assertEqual(settings.intel_lookback_days, 7)

    def test_window_includes_the_start_calendar_day(self) -> None:
        now = datetime(2026, 9, 15, 12, tzinfo=UTC)
        start = window_start(now, timedelta(days=7))
        self.assertEqual(start, datetime(2026, 9, 8, tzinfo=UTC))
        self.assertTrue(
            in_lookback(
                datetime(2026, 9, 8, 7, tzinfo=UTC),
                retrieved_at=now,
                lookback=timedelta(days=7),
            )
        )

    def test_sentinel_timestamp_is_not_this_week(self) -> None:
        now = datetime(2026, 9, 15, 12, tzinfo=UTC)
        self.assertFalse(
            in_lookback(
                datetime(1, 1, 1, tzinfo=UTC),
                retrieved_at=now,
                lookback=timedelta(days=7),
            )
        )
        stale = replace(
            microsoft_advisory(),
            published_at=datetime(1, 1, 1, tzinfo=UTC),
            revised_at=None,
        )
        self.assertFalse(advisory_in_lookback(stale, retrieved_at=now, lookback=timedelta(days=7)))


if __name__ == "__main__":
    unittest.main()
