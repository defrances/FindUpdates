from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from findupdates.applicability import evaluate
from findupdates.applicability.models import (
    ApplicabilityEvidence,
    ApplicabilityResult,
    ApplicabilityVerdict,
    ReasonCode,
)
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
    CvssRecord,
    CvssVersion,
    NormalizedSourceRecord,
    PackageId,
    PackageKind,
    ProductStatus,
    Provenance,
    Remediation,
    RemediationKind,
    TriState,
    UpdateAdvisory,
    UpdateCategory,
    Vendor,
    VendorSeverity,
    normalize_source_record,
)
from findupdates.risk import (
    PolicyResult,
    SeverityBand,
    assess,
    assessment_to_dict,
    canonical_assessment_json,
    load_policy,
)
from findupdates.risk.gates import apply_hard_gates
from findupdates.risk.policy import parse_policy

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "schemas" / "risk-assessment" / "v1.schema.json"
NOW = datetime(2026, 9, 15, 12, tzinfo=UTC)
WINDOWS_CPE = "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:x64:*"
_FIX = (Remediation(RemediationKind.VENDOR_FIX, "vendor patch", None, None),)


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


def _device(
    *,
    stale: bool = False,
    clinical: ClinicalCriticality = ClinicalCriticality.HIGH,
    exposure: NetworkExposure = NetworkExposure.RESTRICTED_LAN,
    hardware: tuple[HardwareComponent, ...] = (),
    software: tuple[SoftwareComponent, ...] = (),
) -> DeviceInventory:
    collected = NOW - timedelta(hours=48) if stale else NOW - timedelta(hours=2)
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
        clinical_criticality=clinical,
        network_exposure=exposure,
        deployment_group="lab-ring-0",
        os=_os(),
        hardware_components=hardware,
        software_components=software,
        inventory_timestamp=collected,
        inventory_source="synthetic-lab-agent",
        source_confidence=VerificationState.VERIFIED,
        freshness_state=freshness,
        freshness_evaluated_at=NOW,
        freshness_max_age_hours=24,
    )


def _advisory(
    *,
    products: tuple[AffectedProduct, ...],
    severity: VendorSeverity = VendorSeverity.HIGH,
    exploited: TriState = TriState.UNKNOWN,
    category: UpdateCategory = UpdateCategory.OS,
    cvss: tuple[CvssRecord, ...] = (),
    remediations: tuple[Remediation, ...] = (),
    vendor: Vendor = Vendor.MICROSOFT,
    vendor_advisory_id: str = "ADV260915",
) -> UpdateAdvisory:
    record = NormalizedSourceRecord(
        vendor=vendor,
        source="test",
        vendor_advisory_id=vendor_advisory_id,
        title="Synthetic risk advisory",
        published_at=datetime(2026, 9, 8, 17, tzinfo=UTC),
        provenance=Provenance(
            source_url="https://example.invalid/advisory",
            raw_sha256="c" * 64,
            retrieved_at=NOW,
            content_type="application/json",
        ),
        cve_ids=("CVE-2026-12345",),
        package_ids=(PackageId(PackageKind.KB, "KB5060001"),),
        vendor_severity=severity,
        cvss=cvss,
        update_category=category,
        known_exploited=exploited,
        affected_products=products,
        remediations=remediations,
    )
    return normalize_source_record(record)


def _windows_product(*, status: ProductStatus = ProductStatus.AFFECTED) -> AffectedProduct:
    return AffectedProduct(
        vendor="microsoft",
        product="Windows 11",
        version_range=">=10.0.22621 <10.0.22631",
        builds=("22621", "22631"),
        architectures=(Architecture.X64,),
        vendor_product_id="windows_11",
        cpe=WINDOWS_CPE,
        status=status,
    )


def _assess(
    *,
    products: tuple[AffectedProduct, ...] | None = None,
    device: DeviceInventory | None = None,
    **advisory_kwargs: object,
):
    advisory = _advisory(
        products=(_windows_product(),) if products is None else products,
        **advisory_kwargs,
    )
    inventory = device or _device()
    applicability = evaluate(advisory, inventory, now=NOW)
    return assess(advisory, inventory, applicability, now=NOW)


def _cvss(score: float, vector: str = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N") -> CvssRecord:
    return CvssRecord(CvssVersion.V3_1, vector, score, "nvd:nvd.nist.gov")


class RiskEngineTests(unittest.TestCase):
    def test_unknown_applicability_blocks_despite_high_cvss(self) -> None:
        result = _assess(
            products=(),
            exploited=TriState.TRUE,
            cvss=(_cvss(9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),),
        )
        self.assertIs(result.policy_result, PolicyResult.BLOCK)
        self.assertIn("UNKNOWN_APPLICABILITY", result.hard_gates_applied)
        self.assertEqual(result.score, min(100, result.score))

    def test_possibly_affected_is_hold(self) -> None:
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
        advisory = _advisory(vendor=Vendor.OTHER, products=(product,))
        device = _device(software=software)
        applicability = evaluate(advisory, device, now=NOW)
        result = assess(advisory, device, applicability, now=NOW)
        self.assertIs(applicability.verdict, ApplicabilityVerdict.POSSIBLY_AFFECTED)
        self.assertIs(result.policy_result, PolicyResult.HOLD)
        self.assertIn("POSSIBLY_AFFECTED", result.hard_gates_applied)

    def test_stale_inventory_holds_affected_device(self) -> None:
        result = _assess(device=_device(stale=True), remediations=_FIX)
        self.assertIs(result.policy_result, PolicyResult.HOLD)
        self.assertIn("STALE_INVENTORY", result.hard_gates_applied)

    def test_firmware_critical_unknown_oem_is_hold(self) -> None:
        hardware = (
            HardwareComponent(
                kind=HardwareKind.BIOS,
                vendor="Example Medical Systems",
                name="ImagingStation-X200 BIOS",
                version="2.7.4",
                verification_state=VerificationState.UNVERIFIED,
                identifiers=NormalizedIdentifiers(),
            ),
        )
        result = _assess(
            category=UpdateCategory.BIOS,
            remediations=_FIX,
            device=_device(clinical=ClinicalCriticality.CRITICAL, hardware=hardware),
        )
        self.assertIs(result.policy_result, PolicyResult.HOLD)
        self.assertIn("FIRMWARE_CRITICAL_UNKNOWN_OEM", result.hard_gates_applied)

    def test_unknown_clinical_criticality_is_hold(self) -> None:
        result = _assess(
            remediations=_FIX,
            device=_device(clinical=ClinicalCriticality.UNKNOWN),
        )
        self.assertIs(result.policy_result, PolicyResult.HOLD)
        self.assertIn("UNKNOWN_CLINICAL_CRITICALITY", result.hard_gates_applied)

    def test_low_confidence_affected_is_hold(self) -> None:
        policy = load_policy()
        advisory = _advisory(products=(_windows_product(),), remediations=_FIX)
        device = _device()
        applicability = ApplicabilityResult(
            result_id="risk_test_low_confidence",
            advisory_id=advisory.advisory_id,
            device_id=device.device_id,
            verdict=ApplicabilityVerdict.AFFECTED,
            confidence=Confidence.LOW,
            blocks_automatic_deployment=True,
            evidence=(
                ApplicabilityEvidence(
                    ReasonCode.VENDOR_AFFECTED,
                    "synthetic low-confidence affected result",
                    ("affected_products",),
                    ("os",),
                ),
            ),
            source_fields=("affected_products",),
            inventory_fields=("os",),
            missing_data=(),
            input_fingerprint="synthetic-low-confidence",
            evaluated_at=NOW,
            needs_reassessment=False,
            previous_fingerprint=None,
        )
        result, gates = apply_hard_gates(
            advisory=advisory,
            device=device,
            applicability=applicability,
            policy=policy,
            band_result=PolicyResult.ALLOW_ANALYSIS,
        )
        self.assertIs(result, PolicyResult.HOLD)
        self.assertIn("LOW_CONFIDENCE_AFFECTED", gates)

    def test_low_band_allows_analysis(self) -> None:
        result = _assess(
            severity=VendorSeverity.NONE,
            remediations=_FIX,
            cvss=(_cvss(1.0),),
            device=_device(
                clinical=ClinicalCriticality.LOW,
                exposure=NetworkExposure.ISOLATED,
            ),
        )
        self.assertIs(result.severity, SeverityBand.LOW)
        self.assertLessEqual(result.score, 29)
        self.assertIs(result.policy_result, PolicyResult.ALLOW_ANALYSIS)

    def test_medium_band_requires_validation(self) -> None:
        result = _assess(remediations=_FIX, cvss=(_cvss(5.0),))
        self.assertIs(result.severity, SeverityBand.MEDIUM)
        self.assertIs(result.policy_result, PolicyResult.REQUIRE_VALIDATION)

    def test_high_cvss_requires_approval_not_deployment(self) -> None:
        result = _assess(
            remediations=_FIX,
            cvss=(_cvss(9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),),
        )
        self.assertIs(result.severity, SeverityBand.HIGH)
        self.assertIs(result.policy_result, PolicyResult.REQUIRE_APPROVAL)

    def test_kev_and_network_cvss_reach_emergency_without_auto_deploy(self) -> None:
        result = _assess(
            exploited=TriState.TRUE,
            severity=VendorSeverity.CRITICAL,
            cvss=(_cvss(9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),),
            device=_device(
                clinical=ClinicalCriticality.CRITICAL,
                exposure=NetworkExposure.INTERNET_EXPOSED,
            ),
        )
        self.assertIs(result.severity, SeverityBand.EMERGENCY)
        self.assertGreaterEqual(result.score, 85)
        self.assertIs(result.policy_result, PolicyResult.REQUIRE_APPROVAL)
        self.assertIn("KEV", result.reason_codes)

    def test_not_affected_stays_allow_analysis(self) -> None:
        result = _assess(
            products=(_windows_product(status=ProductStatus.NOT_AFFECTED),),
            exploited=TriState.TRUE,
            cvss=(_cvss(9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),),
        )
        self.assertIs(result.policy_result, PolicyResult.ALLOW_ANALYSIS)
        self.assertEqual(result.hard_gates_applied, ())
        self.assertIn("NOT_AFFECTED", result.reason_codes)

    def test_identical_inputs_are_byte_stable(self) -> None:
        first = _assess(remediations=_FIX)
        second = _assess(remediations=_FIX)
        self.assertEqual(canonical_assessment_json(first), canonical_assessment_json(second))
        self.assertEqual(first.assessment_id, second.assessment_id)
        self.assertFalse(first.needs_reassessment)

    def test_changed_fingerprint_marks_reassessment(self) -> None:
        result = assess(
            _advisory(products=(_windows_product(),), remediations=_FIX),
            _device(),
            evaluate(
                _advisory(products=(_windows_product(),), remediations=_FIX),
                _device(),
                now=NOW,
            ),
            now=NOW,
            previous_fingerprint="previous-fingerprint",
        )
        self.assertTrue(result.needs_reassessment)

    def test_schema_and_breakdown(self) -> None:
        result = _assess(remediations=_FIX)
        errors = list(
            Draft202012Validator(
                json.loads(SCHEMA_PATH.read_text(encoding="utf-8")),
                format_checker=FormatChecker(),
            ).iter_errors(assessment_to_dict(result))
        )
        self.assertEqual([], errors)
        self.assertTrue(result.contributions)
        self.assertTrue(any(item.points != 0 for item in result.contributions))

    def test_invalid_policy_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            parse_policy({"version": "1.0"}, source_sha256="a" * 64)

    def test_default_policy_loads(self) -> None:
        policy = load_policy()
        self.assertEqual(policy.version, "1.0")
        self.assertEqual(policy.status, "draft")
        self.assertIs(policy.hard_gates["UNKNOWN_APPLICABILITY"], PolicyResult.BLOCK)


if __name__ == "__main__":
    unittest.main()
