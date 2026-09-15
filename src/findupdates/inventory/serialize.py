"""JSON encoding for operator-supplied device inventory."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

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
)

SCHEMA_VERSION = "1.0"


def device_to_dict(device: DeviceInventory) -> dict[str, Any]:
    """Serialize the inventory fields the applicability engine uses."""
    return {
        "schema_version": SCHEMA_VERSION,
        "device_id": device.device_id,
        "manufacturer": device.manufacturer,
        "model": device.model,
        "device_role": device.device_role,
        "clinical_criticality": device.clinical_criticality.value,
        "network_exposure": device.network_exposure.value,
        "deployment_group": device.deployment_group,
        "os": {
            "product": device.os.product,
            "edition": device.os.edition,
            "version": device.os.version,
            "build": device.os.build,
            "architecture": device.os.architecture,
            "vendor_product_id": device.os.vendor_product_id,
            "cpe": device.os.cpe,
            "verification_state": device.os.verification_state.value,
        },
        "hardware_components": [_hardware(item) for item in device.hardware_components],
        "software_components": [_software(item) for item in device.software_components],
        "inventory_timestamp": _datetime(device.inventory_timestamp),
        "inventory_source": device.inventory_source,
        "source_confidence": device.source_confidence.value,
        "freshness_state": device.freshness_state.value,
        "freshness_evaluated_at": _datetime(device.freshness_evaluated_at),
        "freshness_max_age_hours": device.freshness_max_age_hours,
    }


def dict_to_device(payload: dict[str, Any]) -> DeviceInventory:
    """Parse schema-shaped or compact inventory JSON into DeviceInventory."""
    os_raw = payload["os"]
    if not isinstance(os_raw, dict):
        raise ValueError("os must be an object")
    version = payload.get("schema_version", SCHEMA_VERSION)
    if str(version) != SCHEMA_VERSION:
        raise ValueError(f"unsupported inventory schema_version {version}")
    return DeviceInventory(
        device_id=str(payload["device_id"]),
        manufacturer=str(payload["manufacturer"]),
        model=str(payload["model"]),
        device_role=str(payload["device_role"]),
        clinical_criticality=ClinicalCriticality(str(payload["clinical_criticality"])),
        network_exposure=NetworkExposure(str(payload["network_exposure"])),
        deployment_group=str(payload["deployment_group"]),
        os=OperatingSystem(
            product=str(os_raw["product"]),
            edition=_optional_text(os_raw.get("edition")),
            version=_optional_text(os_raw.get("version")),
            build=_optional_text(os_raw.get("build")),
            architecture=str(os_raw["architecture"]),
            vendor_product_id=_optional_text(os_raw.get("vendor_product_id")),
            cpe=_optional_text(os_raw.get("cpe")),
            verification_state=VerificationState(str(os_raw["verification_state"])),
        ),
        hardware_components=tuple(
            _parse_hardware(item) for item in payload.get("hardware_components", [])
        ),
        software_components=tuple(
            _parse_software(item) for item in payload.get("software_components", [])
        ),
        inventory_timestamp=_parse_datetime(str(payload["inventory_timestamp"])),
        inventory_source=str(payload["inventory_source"]),
        source_confidence=VerificationState(str(payload["source_confidence"])),
        freshness_state=FreshnessState(str(payload["freshness_state"])),
        freshness_evaluated_at=_parse_datetime(str(payload["freshness_evaluated_at"])),
        freshness_max_age_hours=int(payload["freshness_max_age_hours"]),
    )


def load_inventory(path: Path) -> tuple[DeviceInventory, ...]:
    """Load one device, a devices catalog, or a JSON array. Empty catalogs fail."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    devices = _devices_from_payload(payload)
    if not devices:
        raise ValueError("inventory catalog is empty")
    return devices


def _devices_from_payload(payload: object) -> tuple[DeviceInventory, ...]:
    if isinstance(payload, list):
        return tuple(_require_object(item) for item in payload)
    if not isinstance(payload, dict):
        raise ValueError("inventory JSON must be an object or array")
    if "devices" in payload:
        raw = payload["devices"]
        if not isinstance(raw, list):
            raise ValueError("devices must be an array")
        return tuple(_require_object(item) for item in raw)
    return (dict_to_device(payload),)


def _require_object(item: object) -> DeviceInventory:
    if not isinstance(item, dict):
        raise ValueError("inventory device must be an object")
    return dict_to_device(item)


def _hardware(item: HardwareComponent) -> dict[str, Any]:
    return {
        "kind": item.kind.value,
        "vendor": item.vendor,
        "name": item.name,
        "version": item.version,
        "verification_state": item.verification_state.value,
        "identifiers": {
            "vendor_product_id": item.identifiers.vendor_product_id,
            "cpe": item.identifiers.cpe,
            "purl": item.identifiers.purl,
        },
    }


def _software(item: SoftwareComponent) -> dict[str, Any]:
    return {
        "kind": item.kind.value,
        "vendor": item.vendor,
        "name": item.name,
        "version": item.version,
        "verification_state": item.verification_state.value,
        "identifiers": {
            "vendor_product_id": item.identifiers.vendor_product_id,
            "cpe": item.identifiers.cpe,
            "purl": item.identifiers.purl,
        },
    }


def _parse_hardware(item: object) -> HardwareComponent:
    if not isinstance(item, dict):
        raise ValueError("hardware component must be an object")
    return HardwareComponent(
        kind=HardwareKind(str(item["kind"])),
        vendor=str(item["vendor"]),
        name=str(item["name"]),
        version=_optional_text(item.get("version")),
        verification_state=VerificationState(str(item["verification_state"])),
        identifiers=_parse_identifiers(item.get("identifiers")),
    )


def _parse_software(item: object) -> SoftwareComponent:
    if not isinstance(item, dict):
        raise ValueError("software component must be an object")
    return SoftwareComponent(
        kind=SoftwareKind(str(item["kind"])),
        vendor=str(item["vendor"]),
        name=str(item["name"]),
        version=_optional_text(item.get("version")),
        verification_state=VerificationState(str(item["verification_state"])),
        identifiers=_parse_identifiers(item.get("identifiers")),
    )


def _parse_identifiers(raw: object) -> NormalizedIdentifiers:
    if raw is None:
        return NormalizedIdentifiers()
    if not isinstance(raw, dict):
        raise ValueError("identifiers must be an object")
    return NormalizedIdentifiers(
        vendor_product_id=_optional_text(raw.get("vendor_product_id")),
        cpe=_optional_text(raw.get("cpe")),
        purl=_optional_text(raw.get("purl")),
    )


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _datetime(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("inventory timestamps must be timezone-aware")
    return parsed
