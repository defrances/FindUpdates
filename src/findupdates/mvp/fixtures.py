"""Synthetic non-PHI Microsoft + Intel + imaging-workstation fixtures for the MVP demo."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

from findupdates.inventory.models import (
    ClinicalCriticality,
    DeviceInventory,
    NetworkExposure,
    OperatingSystem,
    VerificationState,
    evaluate_freshness,
)
from findupdates.normalization.models import (
    AffectedProduct,
    Architecture,
    CvssRecord,
    CvssVersion,
    NormalizedSourceRecord,
    PackageId,
    PackageKind,
    ProductStatus,
    Provenance,
    RebootRequirement,
    Remediation,
    RemediationKind,
    UpdateAdvisory,
    UpdateCategory,
    Vendor,
    VendorSeverity,
    normalize_source_record,
)

NOW = datetime(2026, 9, 15, 18, tzinfo=UTC)
WINDOWS_CPE = "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:x64:*"
REPO_ROOT = Path(__file__).resolve().parents[3]
MSRC_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "msrc" / "2026-sep.json"
INTEL_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "collectors" / "intel-csaf-microcode.json"


def fixture_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def microsoft_advisory(*, injected: str | None = None) -> UpdateAdvisory:
    title = "Windows Kernel Elevation of Privilege Vulnerability"
    description = "Synthetic Microsoft advisory fixture. No production data."
    if injected:
        description = injected
    record = NormalizedSourceRecord(
        vendor=Vendor.MICROSOFT,
        source="msrc",
        vendor_advisory_id="ADV260915",
        title=title,
        description=description,
        published_at=datetime(2026, 9, 8, 17, tzinfo=UTC),
        provenance=Provenance(
            source_url="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-12345",
            raw_sha256=fixture_sha256(MSRC_FIXTURE) if MSRC_FIXTURE.exists() else "a" * 64,
            retrieved_at=NOW,
            content_type="application/json",
        ),
        cve_ids=("CVE-2026-12345",),
        package_ids=(PackageId(PackageKind.KB, "KB5060001"),),
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
        reboot_requirement=RebootRequirement.REQUIRED,
        remediations=(
            Remediation(
                RemediationKind.VENDOR_FIX,
                "Install KB5060001",
                "10.0.22621.4037",
                PackageId(PackageKind.KB, "KB5060001"),
            ),
        ),
        affected_products=(
            AffectedProduct(
                vendor="microsoft",
                product="Windows 11",
                version_range=">=10.0.22621 <10.0.22631",
                builds=("22621", "22631"),
                architectures=(Architecture.X64,),
                vendor_product_id="windows_11",
                cpe=WINDOWS_CPE,
                status=ProductStatus.AFFECTED,
            ),
        ),
    )
    return normalize_source_record(record)


def intel_advisory() -> UpdateAdvisory:
    record = NormalizedSourceRecord(
        vendor=Vendor.INTEL,
        source="intel-csaf",
        vendor_advisory_id="INTEL-SA-01234",
        title="Intel Processor Microcode Update Advisory",
        description=(
            "Synthetic Intel CSAF-style fixture. Vulnerability intelligence only; "
            "not an OEM-qualified firmware package."
        ),
        published_at=datetime(2026, 8, 12, tzinfo=UTC),
        provenance=Provenance(
            source_url="https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01234.html",
            raw_sha256=fixture_sha256(INTEL_FIXTURE) if INTEL_FIXTURE.exists() else "b" * 64,
            retrieved_at=NOW,
            content_type="application/json",
        ),
        cve_ids=("CVE-2026-22222",),
        package_ids=(PackageId(PackageKind.MICROCODE, "mcu-0x00000012"),),
        vendor_severity=VendorSeverity.MEDIUM,
        update_category=UpdateCategory.MICROCODE,
        affected_products=(
            AffectedProduct(
                vendor="intel",
                product="Core i7-1185G7",
                version_range="microcode < 0x00000012",
                builds=(),
                architectures=(Architecture.X64,),
                vendor_product_id="intel-core-i7-1185g7",
                cpe="cpe:2.3:h:intel:core_i7-1185g7:-:*:*:*:*:*:*:*",
                status=ProductStatus.AFFECTED,
            ),
        ),
    )
    return normalize_source_record(record)


def linux_only_advisory() -> UpdateAdvisory:
    record = NormalizedSourceRecord(
        vendor=Vendor.MICROSOFT,
        source="msrc",
        vendor_advisory_id="ADV-LINUX-ONLY",
        title="Unrelated Linux kernel advisory",
        published_at=datetime(2026, 9, 8, 17, tzinfo=UTC),
        provenance=Provenance(
            source_url="https://example.invalid/linux",
            raw_sha256="c" * 64,
            retrieved_at=NOW,
            content_type="application/json",
        ),
        cve_ids=("CVE-2026-99999",),
        vendor_severity=VendorSeverity.HIGH,
        affected_products=(
            AffectedProduct(
                vendor="canonical",
                product="Ubuntu",
                version_range=None,
                builds=(),
                architectures=(Architecture.X64,),
                vendor_product_id="ubuntu_kernel",
                cpe=None,
                status=ProductStatus.AFFECTED,
            ),
        ),
    )
    return normalize_source_record(record)


def imaging_workstation(*, stale: bool = False) -> DeviceInventory:
    collected = NOW - timedelta(days=7 if stale else 0, hours=0 if stale else 2)
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
        clinical_criticality=ClinicalCriticality.HIGH,
        network_exposure=NetworkExposure.RESTRICTED_LAN,
        deployment_group="lab-ring-0",
        os=OperatingSystem(
            product="Windows 11 IoT Enterprise",
            edition="IoT Enterprise",
            version="24H2",
            build="10.0.22621.2500",
            architecture="x64",
            vendor_product_id="windows_11",
            cpe=WINDOWS_CPE,
            verification_state=VerificationState.VERIFIED,
        ),
        hardware_components=(),
        software_components=(),
        inventory_timestamp=collected,
        inventory_source="synthetic-lab-agent",
        source_confidence=VerificationState.VERIFIED,
        freshness_state=freshness,
        freshness_evaluated_at=NOW,
        freshness_max_age_hours=24,
    )
