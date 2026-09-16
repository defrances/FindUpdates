from __future__ import annotations

import datetime
import json
import pathlib
import unittest

import jsonschema

import findupdates.inventory as inventory

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "schemas" / "device-inventory" / "v1.schema.json"
EXAMPLE_PATH = REPO_ROOT / "configs" / "device-models" / "example-windows-intel-device.json"


class DeviceInventorySchemaTests(unittest.TestCase):
    def test_synthetic_example_validates_against_schema(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        example = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(
            schema,
            format_checker=jsonschema.FormatChecker(),
        )

        errors = sorted(validator.iter_errors(example), key=lambda error: list(error.path))

        self.assertEqual([], errors)

    def test_synthetic_workstation_catalog_validates(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        catalog = json.loads(
            (REPO_ROOT / "configs" / "inventory" / "synthetic-workstations.json").read_text(
                encoding="utf-8"
            )
        )
        validator = jsonschema.Draft202012Validator(
            schema,
            format_checker=jsonschema.FormatChecker(),
        )
        devices = catalog["devices"]
        self.assertGreaterEqual(len(devices), 4)
        ids = {item["device_id"] for item in devices}
        self.assertIn("SYNTHETIC-CT-IMG-01", ids)
        self.assertIn("SYNTHETIC-W11-24H2-01", ids)
        errors = []
        for item in devices:
            errors.extend(list(validator.iter_errors(item)))
        self.assertEqual([], errors)

    def test_missing_clinical_criticality_is_rejected(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        example = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))
        del example["clinical_criticality"]
        validator = jsonschema.Draft202012Validator(
            schema,
            format_checker=jsonschema.FormatChecker(),
        )

        self.assertTrue(list(validator.iter_errors(example)))


class InventoryFreshnessTests(unittest.TestCase):
    def test_fresh_inventory(self) -> None:
        collected = datetime.datetime(2026, 9, 15, 12, tzinfo=datetime.UTC)
        evaluated = datetime.datetime(2026, 9, 15, 20, tzinfo=datetime.UTC)

        state = inventory.evaluate_freshness(
            inventory_timestamp=collected,
            evaluated_at=evaluated,
            max_age=datetime.timedelta(hours=24),
        )

        self.assertIs(state, inventory.FreshnessState.FRESH)

    def test_stale_inventory(self) -> None:
        collected = datetime.datetime(2026, 9, 14, 12, tzinfo=datetime.UTC)
        evaluated = datetime.datetime(2026, 9, 15, 20, tzinfo=datetime.UTC)

        state = inventory.evaluate_freshness(
            inventory_timestamp=collected,
            evaluated_at=evaluated,
            max_age=datetime.timedelta(hours=24),
        )

        self.assertIs(state, inventory.FreshnessState.STALE)

    def test_naive_timestamp_is_unknown(self) -> None:
        state = inventory.evaluate_freshness(
            inventory_timestamp=datetime.datetime(2026, 9, 15, 12),
            evaluated_at=datetime.datetime(2026, 9, 15, 20, tzinfo=datetime.UTC),
            max_age=datetime.timedelta(hours=24),
        )

        self.assertIs(state, inventory.FreshnessState.UNKNOWN)


class InventoryModelTests(unittest.TestCase):
    def test_verified_hardware_requires_version(self) -> None:
        with self.assertRaises(ValueError):
            inventory.HardwareComponent(
                kind=inventory.HardwareKind.BIOS,
                vendor="Example Medical Systems",
                name="Synthetic BIOS",
                version=None,
                verification_state=inventory.VerificationState.VERIFIED,
            )


if __name__ == "__main__":
    unittest.main()
