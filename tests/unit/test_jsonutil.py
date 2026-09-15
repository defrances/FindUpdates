"""Vendor JSON datetime helpers reject MSRC sentinels."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime

from findupdates.collectors.jsonutil import parse_datetime


class ParseDatetimeTests(unittest.TestCase):
    def test_iso_timestamp_is_utc(self) -> None:
        self.assertEqual(
            parse_datetime("2026-09-08T07:00:00Z"),
            datetime(2026, 9, 8, 7, tzinfo=UTC),
        )

    def test_msrc_sentinel_is_missing(self) -> None:
        self.assertIsNone(parse_datetime("0001-01-01T00:00:00"))
        self.assertIsNone(parse_datetime(datetime(1, 1, 1, tzinfo=UTC)))


if __name__ == "__main__":
    unittest.main()
