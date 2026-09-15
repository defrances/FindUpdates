from __future__ import annotations

import unittest

from findupdates.logging import get_correlation_id, set_correlation_id


class CorrelationIdTests(unittest.TestCase):
    def test_correlation_id_round_trip(self) -> None:
        set_correlation_id("assessment_123")
        self.assertEqual(get_correlation_id(), "assessment_123")

    def test_empty_correlation_id_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            set_correlation_id("  ")


if __name__ == "__main__":
    unittest.main()
