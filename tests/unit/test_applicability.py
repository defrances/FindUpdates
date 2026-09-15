from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from findupdates.applicability import (
    ApplicabilityVerdict,
    canonical_result_json,
    evaluate,
    evaluate_many,
    result_to_dict,
)
from findupdates.applicability.versions import compare_windows_versions, version_in_range
from findupdates.inventory import (
    ClinicalCriticality,
    DeviceInventory,
    HardwareComponent,
    HardwareKind,
    NetworkExposure,
    NormalizedIdentifiers,
    OperatingSystem,
    SoftwareComponent,
    SoftwareKind,
    VerificationState,
    evaluate_freshness,
)
from findupdates.normalization import (
    AffectedProduct,
    Architecture,
    Confidence,
    NormalizedSourceRecord,
    PackageId,
    PackageKind,
    ProductStatus,
    Provenance,
    Remediation,
    RemediationKind,
    UpdateAdvisory,
    Vendor,
    VendorSeverity,
    normalize_source_record,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "schemas" / "applicability" / "v1.schema.json"
NOW = datetime(2026, 9, 15, 12, tzinfo=UTC)
WINDOWS_CPE = "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:x64:*"


def _os(*, build: str = "10.0.22621.2500", architecture: str = "x64") -> OperatingSystem:
    return OperatingSystem(
        product="Windows 11 IoT Enterprise",
        edition="IoT Enterprise",
        version="24H2",
        build=build,
        architecture=architecture,
        vendor_product_id="windows_11",
        cpe=WINDOWS_CPE,
        verification_state=VerificationState.VERIFIED,
    )


def _device(
    *,
    device_id: str = "SYNTHETIC-MED-001",
    os_record: OperatingSystem | None = None,
    hardware: tuple[HardwareComponent, ...] = (),
    software: tuple[SoftwareComponent, ...] = (),
    stale: bool = False,
    source_confidence: VerificationState = VerificationState.VERIFIED,
) -> DeviceInventory:
    collected = NOW - timedelta(hours=48) if stale else NOW - timedelta(hours=2)
    freshness = evaluate_freshness(
        inventory_timestamp=collected,
        evaluated_at=NOW,
        max_age=timedelta(hours=24),
    )
    return DeviceInventory(
        device_id=device_id,
        manufacturer="Example Medical Systems",
        model="ImagingStation-X200",
        device_role="imaging-workstation",
        clinical_criticality=ClinicalCriticality.HIGH,
        network_exposure=NetworkExposure.RESTRICTED_LAN,
        deployment_group="lab-ring-0",
        os=os_record or _os(),
        hardware_components=hardware,
        software_components=software,
        inventory_timestamp=collected,
        inventory_source="synthetic-lab-agent",
        source_confidence=source_confidence,
        freshness_state=freshness,
        freshness_evaluated_at=NOW,
        freshness_max_age_hours=24,
    )


def _advisory(
    *,
    vendor_advisory_id: str = "ADV260915",
    vendor: Vendor = Vendor.MICROSOFT,
    products: tuple[AffectedProduct, ...],
    remediations: tuple[Remediation, ...] = (),
    revised_at: datetime | None = None,
) -> UpdateAdvisory:
    record = NormalizedSourceRecord(
        vendor=vendor,
        source="test",
        vendor_advisory_id=vendor_advisory_id,
        title="Synthetic applicability advisory",
        published_at=datetime(2026, 9, 8, 17, tzinfo=UTC),
        revised_at=revised_at or datetime(2026, 9, 9, 18, tzinfo=UTC),
        provenance=Provenance(
            source_url="https://example.invalid/advisory",
            raw_sha256="b" * 64,
            retrieved_at=NOW,
            content_type="application/json",
        ),
        cve_ids=("CVE-2026-12345",),
        package_ids=(PackageId(PackageKind.KB, "KB5060001"),),
        vendor_severity=VendorSeverity.HIGH,
        affected_products=products,
        remediations=remediations,
    )
    return normalize_source_record(record)


def _windows_product(
    *,
    status: ProductStatus = ProductStatus.AFFECTED,
    version_range: str | None = ">=10.0.22621 <10.0.22631",
    builds: tuple[str, ...] = ("22621", "22631"),
    architectures: tuple[Architecture, ...] = (Architecture.X64,),
    vendor_product_id: str | None = "windows_11",
    cpe: str | None = WINDOWS_CPE,
    product: str = "Windows 11",
) -> AffectedProduct:
    return AffectedProduct(
        vendor="microsoft",
        product=product,
        version_range=version_range,
        builds=builds,
        architectures=architectures,
        vendor_product_id=vendor_product_id,
        cpe=cpe,
        status=status,
    )


class VersionCompareTests(unittest.TestCase):
    def test_windows_build_numbers_are_compared_not_nt_prefix(self) -> None:
        self.assertEqual(compare_windows_versions("26100.4200", "10.0.22621"), 1)
        self.assertTrue(
            version_in_range("10.0.22621.2500", ">=10.0.22621 <10.0.22631", windows=True)
        )
        self.assertFalse(version_in_range("10.0.22631.0", ">=10.0.22621 <10.0.22631", windows=True))


class ApplicabilityEngineTests(unittest.TestCase):
    def test_windows_in_range_is_affected(self) -> None:
        result = evaluate(
            _advisory(products=(_windows_product(),)),
            _device(),
            now=NOW,
        )
        errors = list(
            Draft202012Validator(
                json.loads(SCHEMA_PATH.read_text(encoding="utf-8")),
                format_checker=FormatChecker(),
            ).iter_errors(result_to_dict(result))
        )
        self.assertEqual([], errors)
        self.assertIs(result.verdict, ApplicabilityVerdict.AFFECTED)
        self.assertIs(result.confidence, Confidence.HIGH)
        self.assertFalse(result.blocks_automatic_deployment)
        self.assertTrue(
            any(item.reason_code.value == "VERSION_IN_RANGE" for item in result.evidence)
        )

    def test_windows_boundary_build_is_not_affected(self) -> None:
        result = evaluate(
            _advisory(products=(_windows_product(),)),
            _device(os_record=_os(build="10.0.22631.0")),
            now=NOW,
        )
        self.assertIs(result.verdict, ApplicabilityVerdict.NOT_AFFECTED)
        self.assertIs(result.confidence, Confidence.HIGH)

    def test_fixed_build_boundary(self) -> None:
        remediations = (
            Remediation(
                kind=RemediationKind.VENDOR_FIX,
                description="Install KB5060001",
                fixed_version="10.0.22621.4037",
                package_id=PackageId(PackageKind.KB, "KB5060001"),
            ),
        )
        product = _windows_product(version_range=None, builds=())
        below = evaluate(
            _advisory(products=(product,), remediations=remediations),
            _device(os_record=_os(build="10.0.22621.4036")),
            now=NOW,
        )
        patched = evaluate(
            _advisory(products=(product,), remediations=remediations),
            _device(os_record=_os(build="10.0.22621.4037")),
            now=NOW,
        )
        self.assertIs(below.verdict, ApplicabilityVerdict.AFFECTED)
        self.assertIs(patched.verdict, ApplicabilityVerdict.NOT_AFFECTED)

    def test_vendor_not_affected_with_product_id(self) -> None:
        result = evaluate(
            _advisory(
                products=(_windows_product(status=ProductStatus.NOT_AFFECTED, version_range=None),)
            ),
            _device(),
            now=NOW,
        )
        self.assertIs(result.verdict, ApplicabilityVerdict.NOT_AFFECTED)
        self.assertTrue(
            any(item.reason_code.value == "VENDOR_NOT_AFFECTED" for item in result.evidence)
        )

    def test_architecture_mismatch_is_not_affected(self) -> None:
        result = evaluate(
            _advisory(products=(_windows_product(architectures=(Architecture.X86,)),)),
            _device(),
            now=NOW,
        )
        self.assertIs(result.verdict, ApplicabilityVerdict.NOT_AFFECTED)
        self.assertTrue(
            any(item.reason_code.value == "ARCHITECTURE_MISMATCH" for item in result.evidence)
        )

    def test_stale_inventory_cannot_be_not_affected(self) -> None:
        result = evaluate(
            _advisory(products=(_windows_product(),)),
            _device(os_record=_os(build="10.0.22631.0"), stale=True),
            now=NOW,
        )
        self.assertIs(result.verdict, ApplicabilityVerdict.POSSIBLY_AFFECTED)
        self.assertTrue(result.blocks_automatic_deployment)
        self.assertTrue(
            any(item.reason_code.value == "STALE_INVENTORY" for item in result.evidence)
        )

    def test_empty_affected_products_is_unknown(self) -> None:
        result = evaluate(_advisory(products=()), _device(), now=NOW)
        self.assertIs(result.verdict, ApplicabilityVerdict.UNKNOWN)
        self.assertTrue(result.blocks_automatic_deployment)

    def test_free_text_name_match_is_possibly_affected(self) -> None:
        product = AffectedProduct(
            vendor="other",
            product="Imaging Console",
            version_range=None,
            builds=(),
            architectures=(),
            vendor_product_id=None,
            cpe=None,
            status=ProductStatus.AFFECTED,
        )
        software = (
            SoftwareComponent(
                kind=SoftwareKind.MEDICAL_APPLICATION,
                vendor="Example Medical Systems",
                name="Imaging Console",
                version="5.4.2",
                verification_state=VerificationState.VERIFIED,
            ),
        )
        result = evaluate(
            _advisory(vendor=Vendor.OTHER, products=(product,)),
            _device(software=software),
            now=NOW,
        )
        self.assertIs(result.verdict, ApplicabilityVerdict.POSSIBLY_AFFECTED)
        self.assertIs(result.confidence, Confidence.LOW)
        self.assertTrue(result.blocks_automatic_deployment)

    def test_intel_driver_version_range(self) -> None:
        product = AffectedProduct(
            vendor="intel",
            product="Example Graphics Driver",
            version_range=">=32.0.101.0001 <32.0.101.1000",
            builds=(),
            architectures=(),
            vendor_product_id="intel:example-graphics-driver",
            cpe=None,
            status=ProductStatus.AFFECTED,
        )
        software = (
            SoftwareComponent(
                kind=SoftwareKind.DRIVER,
                vendor="Intel",
                name="Example Graphics Driver",
                version="32.0.101.0001",
                verification_state=VerificationState.VERIFIED,
                identifiers=NormalizedIdentifiers(
                    vendor_product_id="intel:example-graphics-driver"
                ),
            ),
        )
        in_range = evaluate(
            _advisory(vendor=Vendor.INTEL, products=(product,)),
            _device(software=software),
            now=NOW,
        )
        patched_software = (
            SoftwareComponent(
                kind=SoftwareKind.DRIVER,
                vendor="Intel",
                name="Example Graphics Driver",
                version="32.0.101.1000",
                verification_state=VerificationState.VERIFIED,
                identifiers=NormalizedIdentifiers(
                    vendor_product_id="intel:example-graphics-driver"
                ),
            ),
        )
        out_of_range = evaluate(
            _advisory(vendor=Vendor.INTEL, products=(product,)),
            _device(software=patched_software),
            now=NOW,
        )
        self.assertIs(in_range.verdict, ApplicabilityVerdict.AFFECTED)
        self.assertIs(out_of_range.verdict, ApplicabilityVerdict.NOT_AFFECTED)

    def test_sbom_purl_match(self) -> None:
        product = AffectedProduct(
            vendor="intel",
            product="Example Graphics Driver",
            version_range=None,
            builds=(),
            architectures=(),
            vendor_product_id="intel:example-graphics-driver",
            cpe=None,
            status=ProductStatus.AFFECTED,
        )
        software = (
            SoftwareComponent(
                kind=SoftwareKind.DRIVER,
                vendor="Intel",
                name="Example Graphics Driver",
                version="32.0.101.0001",
                verification_state=VerificationState.VERIFIED,
                identifiers=NormalizedIdentifiers(
                    purl="pkg:generic/intel/example-graphics-driver@32.0.101.0001"
                ),
            ),
        )
        result = evaluate(
            _advisory(vendor=Vendor.INTEL, products=(product,)),
            _device(software=software),
            now=NOW,
        )
        self.assertIs(result.verdict, ApplicabilityVerdict.AFFECTED)
        self.assertTrue(any(item.reason_code.value == "PURL_MATCH" for item in result.evidence))

    def test_missing_component_version_is_possibly_affected(self) -> None:
        product = AffectedProduct(
            vendor="intel",
            product="Example Q-Series Chipset",
            version_range=">=1 <2",
            builds=(),
            architectures=(),
            vendor_product_id="intel:example-q-chipset",
            cpe=None,
            status=ProductStatus.AFFECTED,
        )
        hardware = (
            HardwareComponent(
                kind=HardwareKind.CHIPSET,
                vendor="Intel",
                name="Example Q-Series Chipset",
                version=None,
                verification_state=VerificationState.DECLARED,
                identifiers=NormalizedIdentifiers(vendor_product_id="intel:example-q-chipset"),
            ),
        )
        result = evaluate(
            _advisory(vendor=Vendor.INTEL, products=(product,)),
            _device(hardware=hardware),
            now=NOW,
        )
        self.assertIs(result.verdict, ApplicabilityVerdict.POSSIBLY_AFFECTED)
        self.assertIn("version", result.missing_data)

    def test_idempotent_and_reassessment(self) -> None:
        advisory = _advisory(products=(_windows_product(),))
        device = _device()
        first = evaluate(advisory, device, now=NOW)
        second = evaluate(advisory, device, now=NOW)
        self.assertEqual(canonical_result_json(first), canonical_result_json(second))
        unchanged = evaluate(
            advisory, device, now=NOW, previous_fingerprint=first.input_fingerprint
        )
        self.assertFalse(unchanged.needs_reassessment)
        revised = _advisory(
            products=(_windows_product(),),
            revised_at=datetime(2026, 9, 12, 8, tzinfo=UTC),
        )
        third = evaluate(revised, device, now=NOW, previous_fingerprint=first.input_fingerprint)
        self.assertTrue(third.needs_reassessment)

    def test_bulk_order_is_deterministic(self) -> None:
        first = _advisory(vendor_advisory_id="ADV-B", products=(_windows_product(),))
        second = _advisory(vendor_advisory_id="ADV-A", products=(_windows_product(),))
        device_b = _device(device_id="DEVICE-B")
        device_a = _device(device_id="DEVICE-A")
        results = evaluate_many((first, second), (device_b, device_a), now=NOW)
        pairs = [(item.advisory_id, item.device_id) for item in results]
        self.assertEqual(pairs, sorted(pairs))


if __name__ == "__main__":
    unittest.main()
