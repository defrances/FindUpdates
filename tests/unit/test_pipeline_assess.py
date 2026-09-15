"""Collect-to-change-record assess handoff. Fixture-driven; no live GitHub."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlencode

from findupdates.changerecords import MemoryChangeStore
from findupdates.collectors.http import HttpClient, HttpTransportResult, MappingTransport
from findupdates.enrichment import DEFAULT_KEV_URL, DEFAULT_NVD_URL, EnrichmentService
from findupdates.enrichment.kev import KevClient
from findupdates.enrichment.nvd import NvdClient
from findupdates.inventory import device_to_dict, dict_to_device
from findupdates.mvp.fixtures import NOW, imaging_workstation, intel_advisory, microsoft_advisory
from findupdates.normalization.models import TriState
from findupdates.normalization.serialize import advisory_to_dict
from findupdates.pipeline.__main__ import main
from findupdates.pipeline.assess import AssessOptions, assess_collected
from findupdates.risk.models import PolicyResult

REPO_ROOT = Path(__file__).resolve().parents[2]
ENRICHMENT_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "enrichment"
NVD_URL = f"{DEFAULT_NVD_URL}?{urlencode({'cveId': 'CVE-2026-12345'})}"


def _write_advisories(root: Path, *advisories: object) -> Path:
    folder = root / "advisories" / "msrc"
    folder.mkdir(parents=True, exist_ok=True)
    (root / "advisories" / "summary.json").write_text(
        json.dumps({"correlation_id": "collect-test", "exit_code": 0}) + "\n",
        encoding="utf-8",
    )
    for advisory in advisories:
        payload = advisory_to_dict(advisory)
        path = folder / f"{payload['advisory_id']}.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return root / "advisories"


def _write_inventory(root: Path, stale: bool = False) -> Path:
    path = root / "inventory.json"
    payload = device_to_dict(imaging_workstation(stale=stale))
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


class PipelineAssessTests(unittest.TestCase):
    def test_microsoft_fixture_upserts_one_change_record(self) -> None:
        store = MemoryChangeStore()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            run = assess_collected(
                AssessOptions(
                    advisories=_write_advisories(root, microsoft_advisory()),
                    inventory=_write_inventory(root),
                    output_dir=root / "out",
                    store=store,
                    skip_enrichment=True,
                ),
                now=NOW,
            )
        self.assertEqual(run.exit_code, 0)
        self.assertEqual(len(run.changes), 1)
        row = run.changes[0]
        self.assertEqual(row.deployment_group, "lab-ring-0")
        self.assertIn("affected", row.verdicts)
        self.assertEqual(row.policy_result, PolicyResult.REQUIRE_APPROVAL.value)
        self.assertTrue(row.created)
        stored = store.get(row.idempotency_key)
        self.assertIsNotNone(stored)
        assert stored is not None
        self.assertEqual(stored.device_ids, ("SYNTHETIC-MED-001",))
        self.assertNotIn("token", json.dumps(device_to_dict(imaging_workstation())))

    def test_second_assess_updates_same_idempotency_key(self) -> None:
        store = MemoryChangeStore()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            options = AssessOptions(
                advisories=_write_advisories(root, microsoft_advisory()),
                inventory=_write_inventory(root),
                store=store,
                skip_enrichment=True,
            )
            first = assess_collected(options, now=NOW)
            second = assess_collected(options, now=NOW)
        self.assertTrue(first.changes[0].created)
        self.assertFalse(second.changes[0].created)
        self.assertEqual(first.changes[0].idempotency_key, second.changes[0].idempotency_key)
        self.assertEqual(first.changes[0].issue_number, second.changes[0].issue_number)

    def test_unmatched_intel_still_records_policy(self) -> None:
        store = MemoryChangeStore()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            run = assess_collected(
                AssessOptions(
                    advisories=_write_advisories(root, intel_advisory()),
                    inventory=_write_inventory(root),
                    store=store,
                    skip_enrichment=True,
                ),
                now=NOW,
            )
        self.assertEqual(run.exit_code, 0)
        self.assertEqual(len(run.changes), 1)
        row = run.changes[0]
        self.assertNotEqual(row.verdicts, ("affected",))
        self.assertEqual(row.policy_result, PolicyResult.BLOCK.value)
        self.assertIsNotNone(store.get(row.idempotency_key))

    def test_empty_inventory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            inventory = root / "empty.json"
            inventory.write_text(
                json.dumps({"schema_version": "1.0", "devices": []}) + "\n",
                encoding="utf-8",
            )
            run = assess_collected(
                AssessOptions(
                    advisories=_write_advisories(root, microsoft_advisory()),
                    inventory=inventory,
                    store=MemoryChangeStore(),
                    skip_enrichment=True,
                ),
                now=NOW,
            )
        self.assertEqual(run.exit_code, 1)
        self.assertEqual(run.changes, ())
        self.assertTrue(any("empty" in note for note in run.notes))

    def test_malformed_advisory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            folder = root / "advisories"
            folder.mkdir()
            (folder / "bad.json").write_text("{}\n", encoding="utf-8")
            run = assess_collected(
                AssessOptions(
                    advisories=folder,
                    inventory=_write_inventory(root),
                    store=MemoryChangeStore(),
                    skip_enrichment=True,
                ),
                now=NOW,
            )
        self.assertEqual(run.exit_code, 1)
        self.assertEqual(run.changes, ())

    def test_stale_inventory_still_records_hold(self) -> None:
        store = MemoryChangeStore()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            run = assess_collected(
                AssessOptions(
                    advisories=_write_advisories(root, microsoft_advisory()),
                    inventory=_write_inventory(root, stale=True),
                    store=store,
                    skip_enrichment=True,
                ),
                now=NOW,
            )
        self.assertEqual(run.exit_code, 0)
        self.assertEqual(run.changes[0].policy_result, PolicyResult.HOLD.value)

    def test_example_inventory_file_loads(self) -> None:
        repo = Path(__file__).resolve().parents[2]
        example = repo / "configs" / "device-models" / "example-windows-intel-device.json"
        device = dict_to_device(json.loads(example.read_text(encoding="utf-8")))
        self.assertEqual(device.device_id, "SYNTHETIC-MED-001")
        self.assertEqual(device.deployment_group, "lab-ring-0")

    def test_cli_dry_run_does_not_require_token(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            advisories = _write_advisories(root, microsoft_advisory())
            inventory = _write_inventory(root)
            out = root / "out"
            code = main(
                [
                    "assess",
                    "--advisories",
                    str(advisories),
                    "--inventory",
                    str(inventory),
                    "--output-dir",
                    str(out),
                    "--store",
                    "github",
                    "--dry-run",
                    "--skip-enrichment",
                ],
                environ={},
            )
            self.assertEqual(code, 0)
            summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(len(summary["changes"]), 1)
            self.assertIsNone(summary["changes"][0]["issue_number"])


def _enrichment_service(*, kev_name: str | None = None, down: bool = False) -> EnrichmentService:
    if down:
        responses: dict[str, HttpTransportResult | bytes] = {
            NVD_URL: HttpTransportResult(status=503, body=b"down"),
            DEFAULT_KEV_URL: HttpTransportResult(status=503, body=b"down"),
        }
    else:
        kev_file = "kev-empty.json" if kev_name is None else kev_name
        responses = {
            NVD_URL: (ENRICHMENT_FIXTURES / "nvd-cve-2026-12345.json").read_bytes(),
            DEFAULT_KEV_URL: (ENRICHMENT_FIXTURES / kev_file).read_bytes(),
        }
    client = HttpClient(
        transport=MappingTransport(responses), max_retries=0, min_interval_seconds=0
    )
    return EnrichmentService(
        nvd=NvdClient(client=client),
        kev=KevClient(client=client),
        max_age=timedelta(hours=24),
        now=NOW,
    )


class PipelineAssessEnrichmentTests(unittest.TestCase):
    def test_kev_listing_raises_known_exploited_and_score(self) -> None:
        baseline = MemoryChangeStore()
        listed = MemoryChangeStore()
        advisory = microsoft_advisory()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            skipped = assess_collected(
                AssessOptions(
                    advisories=_write_advisories(root, advisory),
                    inventory=_write_inventory(root),
                    store=baseline,
                    skip_enrichment=True,
                ),
                now=NOW,
            )
            service = _enrichment_service(kev_name="kev-with-cve.json")
            enriched_advisory = service.enrich(advisory).advisory
            self.assertEqual(enriched_advisory.affected_products, advisory.affected_products)
            out = root / "out"
            run = assess_collected(
                AssessOptions(
                    advisories=_write_advisories(root, advisory),
                    inventory=_write_inventory(root),
                    output_dir=out,
                    store=listed,
                    enrichment=service,
                ),
                now=NOW,
            )
            self.assertEqual(skipped.exit_code, 0)
            self.assertEqual(run.exit_code, 0)
            self.assertEqual(skipped.changes[0].known_exploited, TriState.UNKNOWN.value)
            self.assertEqual(run.changes[0].known_exploited, TriState.TRUE.value)
            self.assertGreater(run.changes[0].risk_score, skipped.changes[0].risk_score)
            self.assertTrue((out / "enrichment" / "CVE-2026-12345.json").is_file())

    def test_kev_absence_does_not_force_not_exploited(self) -> None:
        store = MemoryChangeStore()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            run = assess_collected(
                AssessOptions(
                    advisories=_write_advisories(root, microsoft_advisory()),
                    inventory=_write_inventory(root),
                    store=store,
                    enrichment=_enrichment_service(kev_name="kev-empty.json"),
                ),
                now=NOW,
            )
        self.assertEqual(run.exit_code, 0)
        self.assertEqual(run.changes[0].known_exploited, TriState.UNKNOWN.value)

    def test_enrichment_outage_does_not_abort_assess(self) -> None:
        store = MemoryChangeStore()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            run = assess_collected(
                AssessOptions(
                    advisories=_write_advisories(root, microsoft_advisory()),
                    inventory=_write_inventory(root),
                    store=store,
                    enrichment=_enrichment_service(down=True),
                ),
                now=NOW,
            )
        self.assertEqual(run.exit_code, 0)
        self.assertEqual(run.changes[0].known_exploited, TriState.UNKNOWN.value)
        self.assertEqual(run.changes[0].policy_result, PolicyResult.REQUIRE_APPROVAL.value)


if __name__ == "__main__":
    unittest.main()
