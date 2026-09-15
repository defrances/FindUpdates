from __future__ import annotations

import unittest

from findupdates.ids import stable_id


class StableIdTests(unittest.TestCase):
    def test_same_input_produces_same_identifier(self) -> None:
        first = stable_id("advisory", "microsoft", "CVE-2026-12345")
        second = stable_id("advisory", "microsoft", "CVE-2026-12345")
        self.assertEqual(first, second)

    def test_different_input_changes_identifier(self) -> None:
        first = stable_id("device", "device-a")
        second = stable_id("device", "device-b")
        self.assertNotEqual(first, second)

    def test_empty_parts_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            stable_id("device", "")


if __name__ == "__main__":
    unittest.main()
