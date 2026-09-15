"""Device inventory and SBOM handling."""

from findupdates.inventory.models import (
    ClinicalCriticality,
    DeviceInventory,
    FreshnessState,
    HardwareComponent,
    HardwareKind,
    NetworkExposure,
    NormalizedIdentifiers,
    OperatingSystem,
    SoftwareComponent,
    SoftwareKind,
    VerificationState,
    evaluate_freshness,
    refresh_for_assessment,
)
from findupdates.inventory.serialize import (
    device_to_dict,
    dict_to_device,
    load_inventory,
)
from findupdates.inventory.workstations import catalog_path, load_synthetic_workstations

__all__ = [
    "ClinicalCriticality",
    "DeviceInventory",
    "FreshnessState",
    "HardwareComponent",
    "HardwareKind",
    "NetworkExposure",
    "NormalizedIdentifiers",
    "OperatingSystem",
    "SoftwareComponent",
    "SoftwareKind",
    "VerificationState",
    "catalog_path",
    "device_to_dict",
    "dict_to_device",
    "evaluate_freshness",
    "load_inventory",
    "load_synthetic_workstations",
    "refresh_for_assessment",
]
