"""Synthetic non-PHI workstation catalog used by detect/assess."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from findupdates.inventory.models import DeviceInventory
from findupdates.inventory.serialize import load_inventory

REPO_ROOT = Path(__file__).resolve().parents[3]
CATALOG_PATH = REPO_ROOT / "configs" / "inventory" / "synthetic-workstations.json"

WINDOWS_11_CPE = "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:x64:*"
WINDOWS_10_CPE = "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:x64:*"
WINDOWS_11_24H2_CPE = "cpe:2.3:o:microsoft:windows_11_24H2:10.0.26100.4200:*:*:*:*:*:x64:*"
MSRC_WINDOWS_11_24H2_X64 = "12390"
_STAMP = "2026-09-15T12:00:00+00:00"


def catalog_path() -> Path:
    """Return the committed synthetic workstation catalog."""
    return CATALOG_PATH


def load_synthetic_workstations() -> tuple[DeviceInventory, ...]:
    """Load the committed catalog. Empty catalogs are refused by load_inventory."""
    return load_inventory(CATALOG_PATH)


def workstation_catalog_payload() -> dict[str, Any]:
    """Schema-shaped catalog: several realistic lab/clinical workstations, no PHI."""
    return {"schema_version": "1.0", "devices": _stations()}


def _stations() -> list[dict[str, Any]]:
    return [
        _device(
            device_id="SYNTHETIC-CT-IMG-01",
            manufacturer="Example Medical Systems",
            model="CTConsole-A300",
            hardware_revision="B1",
            device_role="ct-imaging-workstation",
            clinical_criticality="high",
            network_exposure="restricted_lan",
            site_group="synthetic-imaging",
            deployment_group="imaging-ct",
            os_product="Windows 11 IoT Enterprise",
            os_edition="IoT Enterprise",
            os_version="22H2",
            os_build="10.0.22621.2500",
            os_vendor_product_id="windows_11",
            os_cpe=WINDOWS_11_CPE,
            cpu_name="Core i7-1185G7",
            cpu_version="0x0000000a",
            cpu_vendor_product_id="intel-core-i7-1185g7",
            cpu_cpe="cpe:2.3:h:intel:core_i7-1185g7:-:*:*:*:*:*:*:*",
            cpu_state="verified",
            app_name="CT Acquisition Console",
            app_version="4.2.1",
        ),
        _device(
            device_id="SYNTHETIC-MR-IMG-01",
            manufacturer="Example Medical Systems",
            model="MRConsole-R200",
            hardware_revision="C3",
            device_role="mr-imaging-workstation",
            clinical_criticality="critical",
            network_exposure="restricted_lan",
            site_group="synthetic-imaging",
            deployment_group="imaging-mr",
            os_product="Windows 11 IoT Enterprise",
            os_edition="IoT Enterprise",
            os_version="22H2",
            os_build="10.0.22621.2500",
            os_vendor_product_id="windows_11",
            os_cpe=WINDOWS_11_CPE,
            cpu_name="Example Intel CPU Family",
            cpu_version="family-13",
            cpu_vendor_product_id="intel:example-cpu-family-13",
            cpu_cpe=None,
            cpu_state="declared",
            app_name="MR Review Console",
            app_version="6.1.0",
        ),
        _device(
            device_id="SYNTHETIC-PACS-01",
            manufacturer="Example Imaging Informatics",
            model="PACS-Review-21",
            hardware_revision="A1",
            device_role="pacs-review-workstation",
            clinical_criticality="medium",
            network_exposure="isolated",
            site_group="synthetic-reading-room",
            deployment_group="pacs-review",
            os_product="Windows 11 IoT Enterprise",
            os_edition="IoT Enterprise",
            os_version="22H2",
            os_build="10.0.22621.2500",
            os_vendor_product_id="windows_11",
            os_cpe=WINDOWS_11_CPE,
            cpu_name=None,
            app_name="PACS Viewer",
            app_version="12.3.4",
        ),
        _device(
            device_id="SYNTHETIC-US-01",
            manufacturer="Example Medical Systems",
            model="UltrasoundCart-U90",
            hardware_revision="D2",
            device_role="ultrasound-workstation",
            clinical_criticality="high",
            network_exposure="restricted_lan",
            site_group="synthetic-point-of-care",
            deployment_group="ultrasound",
            os_product="Windows 10 IoT Enterprise",
            os_edition="IoT Enterprise",
            os_version="21H2",
            os_build="10.0.19044.3803",
            os_vendor_product_id="windows_10",
            os_cpe=WINDOWS_10_CPE,
            cpu_name="Core i7-1185G7",
            cpu_version="0x0000000a",
            cpu_vendor_product_id="intel-core-i7-1185g7",
            cpu_cpe="cpe:2.3:h:intel:core_i7-1185g7:-:*:*:*:*:*:*:*",
            cpu_state="verified",
            app_name="Ultrasound Scan App",
            app_version="3.8.2",
        ),
        _device(
            device_id="SYNTHETIC-LAB-24H2-01",
            manufacturer="Example Medical Systems",
            model="LabBench-L110",
            hardware_revision="A2",
            device_role="lab-analysis-workstation",
            clinical_criticality="high",
            network_exposure="restricted_lan",
            site_group="synthetic-lab",
            deployment_group="lab-ring-0",
            os_product="Windows 11 IoT Enterprise",
            os_edition="IoT Enterprise",
            os_version="24H2",
            os_build="10.0.26100.4200",
            os_vendor_product_id="windows_11",
            os_cpe=WINDOWS_11_CPE,
            cpu_name="Example Intel CPU Family",
            cpu_version="family-13",
            cpu_vendor_product_id="intel:example-cpu-family-13",
            cpu_cpe=None,
            cpu_state="declared",
            app_name="Lab Instrument Console",
            app_version="2.0.9",
        ),
        _device(
            device_id="SYNTHETIC-WKLIST-01",
            manufacturer="Example Health IT",
            model="Worklist-PC-5",
            hardware_revision="A0",
            device_role="worklist-workstation",
            clinical_criticality="low",
            network_exposure="enterprise_lan",
            site_group="synthetic-admin",
            deployment_group="worklist",
            os_product="Windows 11 IoT Enterprise",
            os_edition="IoT Enterprise",
            os_version="22H2",
            os_build="10.0.22621.2500",
            os_vendor_product_id="windows_11",
            os_cpe=WINDOWS_11_CPE,
            cpu_name=None,
            app_name="Radiology Worklist",
            app_version="1.4.0",
        ),
        _device(
            device_id="SYNTHETIC-W11-24H2-01",
            manufacturer="Example Imaging Informatics",
            model="PACS-Validate-24H2",
            hardware_revision="A1",
            device_role="pacs-review-workstation",
            clinical_criticality="medium",
            network_exposure="restricted_lan",
            site_group="synthetic-reading-room",
            deployment_group="pacs-validate",
            os_product="Windows 11 Version 24H2 for x64-based Systems",
            os_edition="IoT Enterprise",
            os_version="24H2",
            os_build="10.0.26100.4200",
            os_vendor_product_id=MSRC_WINDOWS_11_24H2_X64,
            os_cpe=WINDOWS_11_24H2_CPE,
            cpu_name="Core i7-1185G7",
            cpu_version="0x0000000a",
            cpu_vendor_product_id="intel-core-i7-1185g7",
            cpu_cpe="cpe:2.3:h:intel:core_i7-1185g7:-:*:*:*:*:*:*:*",
            cpu_state="verified",
            app_name="PACS Validation Viewer",
            app_version="12.3.4",
        ),
    ]


def _device(
    *,
    device_id: str,
    manufacturer: str,
    model: str,
    hardware_revision: str,
    device_role: str,
    clinical_criticality: str,
    network_exposure: str,
    site_group: str,
    deployment_group: str,
    os_product: str,
    os_edition: str,
    os_version: str,
    os_build: str,
    os_vendor_product_id: str,
    os_cpe: str,
    cpu_name: str | None,
    app_name: str,
    app_version: str,
    cpu_version: str | None = None,
    cpu_vendor_product_id: str | None = None,
    cpu_cpe: str | None = None,
    cpu_state: str = "declared",
) -> dict[str, Any]:
    hardware: list[dict[str, Any]] = []
    if cpu_name is not None:
        hardware.append(
            {
                "kind": "cpu",
                "vendor": "Intel",
                "name": cpu_name,
                "version": cpu_version,
                "verification_state": cpu_state,
                "identifiers": {
                    "vendor_product_id": cpu_vendor_product_id,
                    "cpe": cpu_cpe,
                    "purl": None,
                },
            }
        )
        hardware.append(
            {
                "kind": "bios",
                "vendor": manufacturer,
                "name": f"{model} BIOS",
                "version": "2.1.0",
                "verification_state": "verified",
                "identifiers": {
                    "vendor_product_id": f"{device_id.lower()}:bios",
                    "cpe": None,
                    "purl": None,
                },
            }
        )
    return {
        "schema_version": "1.0",
        "device_id": device_id,
        "manufacturer": manufacturer,
        "model": model,
        "hardware_revision": hardware_revision,
        "device_role": device_role,
        "clinical_criticality": clinical_criticality,
        "network_exposure": network_exposure,
        "site_group": site_group,
        "deployment_group": deployment_group,
        "validation_baseline": "BASELINE-2026-09",
        "maintenance_window": {
            "timezone": "Europe/Madrid",
            "days_of_week": ["sun"],
            "start_local": "02:00",
            "duration_minutes": 120,
        },
        "update_management": {
            "mechanism": "intune",
            "channel": "medical-validation",
        },
        "os": {
            "product": os_product,
            "edition": os_edition,
            "version": os_version,
            "build": os_build,
            "architecture": "x64",
            "vendor_product_id": os_vendor_product_id,
            "cpe": os_cpe,
            "verification_state": "verified",
        },
        "hardware_components": hardware,
        "software_components": [
            {
                "kind": "medical_application",
                "vendor": manufacturer,
                "name": app_name,
                "version": app_version,
                "verification_state": "verified",
                "identifiers": {
                    "vendor_product_id": f"{device_id.lower()}:app",
                    "cpe": None,
                    "purl": None,
                },
            }
        ],
        "sbom_references": [
            {
                "format": "cyclonedx",
                "document_ref": f"synthetic://sbom/{device_id}/cyclonedx.json",
                "document_version": "1.6",
                "sha256": None,
            }
        ],
        "inventory_timestamp": _STAMP,
        "inventory_source": "synthetic-lab-agent",
        "source_confidence": "verified",
        "freshness_state": "fresh",
        "freshness_evaluated_at": "2026-09-15T14:00:00+00:00",
        "freshness_max_age_hours": 8760,
    }
