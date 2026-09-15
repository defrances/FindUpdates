from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from findupdates.normalization import (
    AffectedProduct,
    Architecture,
    Completeness,
    Confidence,
    CvssRecord,
    CvssVersion,
    Exploitability,
    FieldProvenance,
    NormalizedSourceRecord,
    PackageId,
    PackageKind,
    ProductStatus,
    Provenance,
    RebootRequirement,
    TriState,
    UpdateCategory,
    Vendor,
    VendorSeverity,
    advisory_to_dict,
    canonical_json,
    logical_advisory_key,
    merge_advisories,
    normalize_source_record,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "schemas" / "update-advisory" / "v1.schema.json"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "update-advisory"


def _validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _load_fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _provenance(digest: str = "a" * 64) -> Provenance:
    return Provenance(
        source_url="https://example.invalid/advisory",
        raw_sha256=digest,
        retrieved_at=datetime(2026, 9, 15, 12, tzinfo=UTC),
        content_type="application/json",
    )


class UpdateAdvisorySchemaTests(unittest.TestCase):
    def test_microsoft_fixture_validates(self) -> None:
        errors = sorted(
            _validator().iter_errors(_load_fixture("microsoft-windows-cve.json")),
            key=lambda error: list(error.path),
        )
        self.assertEqual([], errors)

    def test_intel_fixture_validates(self) -> None:
        errors = sorted(
            _validator().iter_errors(_load_fixture("intel-csaf-microcode.json")),
            key=lambda error: list(error.path),
        )
        self.assertEqual([], errors)

    def test_unknown_fields_fixture_validates(self) -> None:
        errors = sorted(
            _validator().iter_errors(_load_fixture("unknown-fields.json")),
            key=lambda error: list(error.path),
        )
        self.assertEqual([], errors)

    def test_boolean_known_exploited_is_rejected(self) -> None:
        payload = _load_fixture("microsoft-windows-cve.json")
        payload["known_exploited"] = False
        self.assertTrue(list(_validator().iter_errors(payload)))

    def test_missing_schema_version_is_rejected(self) -> None:
        payload = _load_fixture("unknown-fields.json")
        del payload["schema_version"]
        self.assertTrue(list(_validator().iter_errors(payload)))


class NormalizationTests(unittest.TestCase):
    def test_vendor_advisory_id_produces_stable_identity(self) -> None:
        first = normalize_source_record(self._microsoft_record())
        second = normalize_source_record(self._microsoft_record())
        expected = logical_advisory_key(
            vendor=Vendor.MICROSOFT,
            vendor_advisory_id="ADV260915",
            cve_ids=("CVE-2026-12345",),
            raw_sha256="a" * 64,
        )
        self.assertEqual(first.advisory_id, second.advisory_id)
        self.assertEqual(first.advisory_id, expected)

    def test_missing_vendor_id_falls_back_to_cve_set(self) -> None:
        record = NormalizedSourceRecord(
            vendor=Vendor.INTEL,
            source="intel-csaf",
            vendor_advisory_id=None,
            title="Intel advisory without vendor ID",
            published_at=datetime(2026, 8, 12, tzinfo=UTC),
            provenance=_provenance("b" * 64),
            cve_ids=("CVE-2026-22222",),
        )
        advisory = normalize_source_record(record)
        self.assertEqual(
            advisory.advisory_id,
            logical_advisory_key(
                vendor=Vendor.INTEL,
                vendor_advisory_id=None,
                cve_ids=("CVE-2026-22222",),
                raw_sha256="b" * 64,
            ),
        )

    def test_absent_exploitation_stays_unknown(self) -> None:
        advisory = normalize_source_record(self._microsoft_record())
        self.assertIs(advisory.known_exploited, TriState.UNKNOWN)
        self.assertNotEqual(advisory.known_exploited, TriState.FALSE)
        self.assertIn("known_exploited", advisory.incomplete_fields)

    def test_empty_affected_products_is_partial_not_not_affected(self) -> None:
        record = NormalizedSourceRecord(
            vendor=Vendor.OTHER,
            source="synthetic",
            vendor_advisory_id=None,
            title="Incomplete synthetic advisory",
            published_at=datetime(2026, 9, 15, tzinfo=UTC),
            provenance=_provenance("c" * 64),
        )
        advisory = normalize_source_record(record)
        self.assertEqual(advisory.affected_products, ())
        self.assertIs(advisory.completeness, Completeness.UNKNOWN)
        self.assertIn("affected_products", advisory.incomplete_fields)

    def test_normalized_output_matches_schema(self) -> None:
        advisory = normalize_source_record(self._microsoft_record())
        errors = list(_validator().iter_errors(advisory_to_dict(advisory)))
        self.assertEqual([], errors)

    def _microsoft_record(self) -> NormalizedSourceRecord:
        return NormalizedSourceRecord(
            vendor=Vendor.MICROSOFT,
            source="msrc",
            vendor_advisory_id="ADV260915",
            title="Windows Kernel Elevation of Privilege Vulnerability",
            description="Synthetic Microsoft advisory fixture. No production data.",
            published_at=datetime(2026, 9, 8, 17, tzinfo=UTC),
            revised_at=datetime(2026, 9, 9, 18, 30, tzinfo=UTC),
            collected_at=datetime(2026, 9, 15, 12, tzinfo=UTC),
            provenance=_provenance(),
            cve_ids=("CVE-2026-12345",),
            package_ids=(PackageId(PackageKind.KB, "KB5060001"),),
            references=("https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12345",),
            vendor_severity=VendorSeverity.HIGH,
            cvss=(
                CvssRecord(
                    version=CvssVersion.V3_1,
                    vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                    base_score=7.8,
                    source="msrc",
                ),
            ),
            update_category=UpdateCategory.OS,
            reboot_requirement=RebootRequirement.MAYBE,
            known_exploited=TriState.UNKNOWN,
            exploitability=Exploitability.UNKNOWN,
            affected_products=(
                AffectedProduct(
                    vendor="microsoft",
                    product="Windows 11",
                    version_range=">=10.0.22621 <10.0.22631",
                    builds=("22621", "22631"),
                    architectures=(Architecture.X64,),
                    vendor_product_id="windows_11",
                    cpe="cpe:2.3:o:microsoft:windows_11:-:*:*:*:*:*:x64:*",
                    status=ProductStatus.AFFECTED,
                ),
            ),
            field_provenance=(
                FieldProvenance("cve_ids", "msrc"),
                FieldProvenance("reboot_requirement", "msrc"),
            ),
            normalization_confidence=Confidence.UNKNOWN,
        )


class MergeAndHashTests(unittest.TestCase):
    def test_unknown_does_not_overwrite_asserted_reboot(self) -> None:
        first = normalize_source_record(
            NormalizedSourceRecord(
                vendor=Vendor.MICROSOFT,
                source="msrc",
                vendor_advisory_id="ADV260915",
                title="Windows advisory",
                published_at=datetime(2026, 9, 8, tzinfo=UTC),
                provenance=_provenance(),
                reboot_requirement=RebootRequirement.REQUIRED,
            )
        )
        second = normalize_source_record(
            NormalizedSourceRecord(
                vendor=Vendor.MICROSOFT,
                source="msrc",
                vendor_advisory_id="ADV260915",
                title="Windows advisory revision",
                published_at=datetime(2026, 9, 8, tzinfo=UTC),
                revised_at=datetime(2026, 9, 10, tzinfo=UTC),
                provenance=_provenance("d" * 64),
                reboot_requirement=RebootRequirement.UNKNOWN,
            )
        )
        merged = merge_advisories(first, second)
        self.assertIs(merged.reboot_requirement, RebootRequirement.REQUIRED)
        self.assertEqual(merged.conflicts, ())

    def test_conflicting_assertions_become_unknown(self) -> None:
        first = normalize_source_record(
            NormalizedSourceRecord(
                vendor=Vendor.MICROSOFT,
                source="msrc",
                vendor_advisory_id="ADV260915",
                title="Windows advisory",
                published_at=datetime(2026, 9, 8, tzinfo=UTC),
                provenance=_provenance(),
                reboot_requirement=RebootRequirement.REQUIRED,
            )
        )
        second = normalize_source_record(
            NormalizedSourceRecord(
                vendor=Vendor.MICROSOFT,
                source="msrc",
                vendor_advisory_id="ADV260915",
                title="Windows advisory revision",
                published_at=datetime(2026, 9, 8, tzinfo=UTC),
                revised_at=datetime(2026, 9, 10, tzinfo=UTC),
                provenance=_provenance("e" * 64),
                reboot_requirement=RebootRequirement.NO,
            )
        )
        merged = merge_advisories(first, second)
        self.assertIs(merged.reboot_requirement, RebootRequirement.UNKNOWN)
        self.assertEqual(merged.conflicts[0].field_path, "reboot_requirement")
        self.assertIs(merged.normalization_confidence, Confidence.LOW)

    def test_canonical_json_is_stable(self) -> None:
        advisory = normalize_source_record(
            NormalizedSourceRecord(
                vendor=Vendor.INTEL,
                source="intel-csaf",
                vendor_advisory_id="INTEL-SA-01234",
                title="Intel Processor Microcode Update Advisory",
                published_at=datetime(2026, 8, 12, tzinfo=UTC),
                provenance=_provenance("b" * 64),
                cve_ids=("CVE-2026-22222",),
            )
        )
        self.assertEqual(canonical_json(advisory), canonical_json(advisory))

    def test_different_identities_cannot_merge(self) -> None:
        left = normalize_source_record(
            NormalizedSourceRecord(
                vendor=Vendor.MICROSOFT,
                source="msrc",
                vendor_advisory_id="ADV-A",
                title="A",
                published_at=datetime(2026, 9, 8, tzinfo=UTC),
                provenance=_provenance(),
            )
        )
        right = normalize_source_record(
            NormalizedSourceRecord(
                vendor=Vendor.MICROSOFT,
                source="msrc",
                vendor_advisory_id="ADV-B",
                title="B",
                published_at=datetime(2026, 9, 8, tzinfo=UTC),
                provenance=_provenance("f" * 64),
            )
        )
        with self.assertRaises(ValueError):
            merge_advisories(left, right)


if __name__ == "__main__":
    unittest.main()
