from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from findupdates.applicability import evaluate
from findupdates.changerecords import (
    MemoryChangeStore,
    PromotionDenied,
    assert_workflow_gate,
    build_change_record,
    idempotency_key,
    parse_issue_body,
    promote,
    record_to_dict,
    render_github_issue,
)
from findupdates.changerecords.workflow import main as workflow_main
from findupdates.inventory import (
    ClinicalCriticality,
    DeviceInventory,
    NetworkExposure,
    OperatingSystem,
    VerificationState,
    evaluate_freshness,
)
from findupdates.normalization import (
    AffectedProduct,
    Architecture,
    CvssRecord,
    CvssVersion,
    NormalizedSourceRecord,
    ProductStatus,
    Provenance,
    TriState,
    UpdateAdvisory,
    Vendor,
    VendorSeverity,
    normalize_source_record,
)
from findupdates.risk import assess

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "schemas" / "change-record" / "v1.schema.json"
NOW = datetime(2026, 9, 15, 12, tzinfo=UTC)
WINDOWS_CPE = "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:x64:*"


def _os() -> OperatingSystem:
    return OperatingSystem(
        product="Windows 11 IoT Enterprise",
        edition="IoT Enterprise",
        version="24H2",
        build="10.0.22621.2500",
        architecture="x64",
        vendor_product_id="windows_11",
        cpe=WINDOWS_CPE,
        verification_state=VerificationState.VERIFIED,
    )


def _device() -> DeviceInventory:
    collected = NOW - timedelta(hours=2)
    freshness = evaluate_freshness(
        inventory_timestamp=collected,
        evaluated_at=NOW,
        max_age=timedelta(hours=24),
    )
    return DeviceInventory(
        device_id="SYNTHETIC-MED-001",
        manufacturer="Example Medical Systems",
        model="ImagingStation-X200",
        device_role="imaging-workstation",
        clinical_criticality=ClinicalCriticality.CRITICAL,
        network_exposure=NetworkExposure.INTERNET_EXPOSED,
        deployment_group="lab-ring-0",
        os=_os(),
        hardware_components=(),
        software_components=(),
        inventory_timestamp=collected,
        inventory_source="synthetic-lab-agent",
        source_confidence=VerificationState.VERIFIED,
        freshness_state=freshness,
        freshness_evaluated_at=NOW,
        freshness_max_age_hours=24,
    )


def _advisory(*, products: tuple[AffectedProduct, ...] | None = None) -> UpdateAdvisory:
    windows = AffectedProduct(
        vendor="microsoft",
        product="Windows 11",
        version_range=">=10.0.22621 <10.0.22631",
        builds=("22621", "22631"),
        architectures=(Architecture.X64,),
        vendor_product_id="windows_11",
        cpe=WINDOWS_CPE,
        status=ProductStatus.AFFECTED,
    )
    record = NormalizedSourceRecord(
        vendor=Vendor.MICROSOFT,
        source="test",
        vendor_advisory_id="ADV260915",
        title="Windows Kernel Elevation of Privilege Vulnerability",
        published_at=datetime(2026, 9, 8, 17, tzinfo=UTC),
        provenance=Provenance(
            source_url="https://example.invalid/advisory",
            raw_sha256="e" * 64,
            retrieved_at=NOW,
            content_type="application/json",
        ),
        cve_ids=("CVE-2026-12345",),
        vendor_severity=VendorSeverity.CRITICAL,
        known_exploited=TriState.TRUE,
        cvss=(
            CvssRecord(
                CvssVersion.V3_1,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                9.8,
                "nvd:nvd.nist.gov",
            ),
        ),
        affected_products=(windows,) if products is None else products,
    )
    return normalize_source_record(record)


def _assessed(*, products: tuple[AffectedProduct, ...] | None = None):
    advisory = _advisory(products=products)
    device = _device()
    applicability = evaluate(advisory, device, now=NOW)
    risk = assess(advisory, device, applicability, now=NOW)
    record = build_change_record(
        advisory,
        (device,),
        (applicability,),
        (risk,),
        now=NOW,
    )
    return advisory, device, risk, record


class ChangeRecordTests(unittest.TestCase):
    def test_high_assessment_creates_complete_record(self) -> None:
        _advisory_obj, device, risk, record = _assessed()
        self.assertGreaterEqual(risk.score, 50)
        self.assertIn(device.device_id, record.device_ids)
        self.assertTrue(record.evidence_links)
        self.assertIn("risk:", " ".join(record.evidence_links))
        errors = list(
            Draft202012Validator(
                json.loads(SCHEMA_PATH.read_text(encoding="utf-8")),
                format_checker=FormatChecker(),
            ).iter_errors(record_to_dict(record))
        )
        self.assertEqual([], errors)

    def test_repeated_scan_updates_same_issue(self) -> None:
        _, _, _, first = _assessed()
        _, _, _, second = _assessed()
        self.assertEqual(first.idempotency_key, second.idempotency_key)
        store = MemoryChangeStore()
        created = store.upsert(first)
        updated = store.upsert(second)
        self.assertTrue(created.created)
        self.assertFalse(updated.created)
        self.assertEqual(created.issue_number, updated.issue_number)
        self.assertIs(store.get(first.idempotency_key) is not None, True)

    def test_block_cannot_be_promoted_by_environment_choice(self) -> None:
        _, _, risk, record = _assessed(products=())
        self.assertEqual(risk.policy_result.value, "BLOCK")
        with self.assertRaises(PromotionDenied):
            promote(
                record,
                target_environment="production",
                actor="engineer",
                reason="override via workflow input",
                now=NOW,
                environment_approved=True,
            )
        with self.assertRaises(PromotionDenied):
            assert_workflow_gate(record, "production")

    def test_hold_cannot_reach_canary(self) -> None:
        advisory = _advisory()
        device = _device()
        # Stale inventory forces HOLD on an otherwise matching device.
        stale = DeviceInventory(
            device_id=device.device_id,
            manufacturer=device.manufacturer,
            model=device.model,
            device_role=device.device_role,
            clinical_criticality=device.clinical_criticality,
            network_exposure=device.network_exposure,
            deployment_group=device.deployment_group,
            os=device.os,
            hardware_components=(),
            software_components=(),
            inventory_timestamp=NOW - timedelta(hours=48),
            inventory_source=device.inventory_source,
            source_confidence=device.source_confidence,
            freshness_state=evaluate_freshness(
                inventory_timestamp=NOW - timedelta(hours=48),
                evaluated_at=NOW,
                max_age=timedelta(hours=24),
            ),
            freshness_evaluated_at=NOW,
            freshness_max_age_hours=24,
        )
        applicability = evaluate(advisory, stale, now=NOW)
        risk = assess(advisory, stale, applicability, now=NOW)
        record = build_change_record(advisory, (stale,), (applicability,), (risk,), now=NOW)
        self.assertEqual(record.policy_result, "HOLD")
        with self.assertRaises(PromotionDenied):
            promote(
                record,
                target_environment="canary",
                actor="engineer",
                reason="please ship",
                now=NOW,
                environment_approved=True,
            )

    def test_workflow_cli_reads_policy_from_file_not_argv(self) -> None:
        _, _, _, record = _assessed(products=())
        payload = record_to_dict(record)
        payload["policy_result"] = "BLOCK"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "record.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(workflow_main([str(path), "production"]), 1)
            self.assertEqual(workflow_main([str(path), "lab"]), 0)

    def test_issue_body_round_trip_and_labels(self) -> None:
        _, _, _, record = _assessed()
        issue = render_github_issue(record)
        parsed = parse_issue_body(str(issue["body"]))
        self.assertEqual(parsed.idempotency_key, record.idempotency_key)
        self.assertIn(record.idempotency_key, issue["labels"])
        self.assertEqual(
            idempotency_key(record.advisory_ids[0], record.deployment_group),
            record.idempotency_key,
        )

    def test_production_requires_environment_approval(self) -> None:
        _, _, risk, record = _assessed()
        if risk.policy_result.value in {"HOLD", "BLOCK"}:
            self.skipTest("unexpected hard gate on high CVSS fixture")
        with self.assertRaises(PromotionDenied):
            promote(
                record,
                target_environment="production",
                actor="engineer",
                reason="no environment approval yet",
                now=NOW,
                environment_approved=False,
            )


if __name__ == "__main__":
    unittest.main()
