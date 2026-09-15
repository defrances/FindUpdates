"""Strongly typed device-inventory domain model and freshness rules."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum


class VerificationState(StrEnum):
    VERIFIED = "verified"
    DECLARED = "declared"
    UNVERIFIED = "unverified"
    UNKNOWN = "unknown"


class ClinicalCriticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class NetworkExposure(StrEnum):
    ISOLATED = "isolated"
    RESTRICTED_LAN = "restricted_lan"
    ENTERPRISE_LAN = "enterprise_lan"
    INTERNET_EXPOSED = "internet_exposed"
    UNKNOWN = "unknown"


class FreshnessState(StrEnum):
    FRESH = "fresh"
    STALE = "stale"
    UNKNOWN = "unknown"


class HardwareKind(StrEnum):
    CPU = "cpu"
    CHIPSET = "chipset"
    BIOS = "bios"
    FIRMWARE = "firmware"
    OTHER = "other"


class SoftwareKind(StrEnum):
    DRIVER = "driver"
    MEDICAL_APPLICATION = "medical_application"
    SYSTEM_SOFTWARE = "system_software"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class NormalizedIdentifiers:
    """Identifiers used for deterministic matching against advisory/SBOM metadata."""

    vendor_product_id: str | None = None
    cpe: str | None = None
    purl: str | None = None


@dataclass(frozen=True, slots=True)
class OperatingSystem:
    product: str
    edition: str | None
    version: str | None
    build: str | None
    architecture: str
    vendor_product_id: str | None
    cpe: str | None
    verification_state: VerificationState

    def __post_init__(self) -> None:
        _require_text("os.product", self.product)
        is_verified_without_version = (
            self.verification_state is VerificationState.VERIFIED
            and not (self.version or self.build)
        )
        if is_verified_without_version:
            raise ValueError("verified OS inventory requires version or build")


@dataclass(frozen=True, slots=True)
class HardwareComponent:
    kind: HardwareKind
    vendor: str
    name: str
    version: str | None
    verification_state: VerificationState
    identifiers: NormalizedIdentifiers = NormalizedIdentifiers()

    def __post_init__(self) -> None:
        _require_text("hardware.vendor", self.vendor)
        _require_text("hardware.name", self.name)
        _require_verified_version(self.verification_state, self.version, "hardware component")


@dataclass(frozen=True, slots=True)
class SoftwareComponent:
    kind: SoftwareKind
    vendor: str
    name: str
    version: str | None
    verification_state: VerificationState
    identifiers: NormalizedIdentifiers = NormalizedIdentifiers()

    def __post_init__(self) -> None:
        _require_text("software.vendor", self.vendor)
        _require_text("software.name", self.name)
        _require_verified_version(self.verification_state, self.version, "software component")


@dataclass(frozen=True, slots=True)
class DeviceInventory:
    """Non-PHI technical inventory required for update applicability decisions."""

    device_id: str
    manufacturer: str
    model: str
    device_role: str
    clinical_criticality: ClinicalCriticality
    network_exposure: NetworkExposure
    deployment_group: str
    os: OperatingSystem
    hardware_components: tuple[HardwareComponent, ...]
    software_components: tuple[SoftwareComponent, ...]
    inventory_timestamp: datetime
    inventory_source: str
    source_confidence: VerificationState
    freshness_state: FreshnessState
    freshness_evaluated_at: datetime
    freshness_max_age_hours: int

    def __post_init__(self) -> None:
        for field_name, value in (
            ("device_id", self.device_id),
            ("manufacturer", self.manufacturer),
            ("model", self.model),
            ("device_role", self.device_role),
            ("deployment_group", self.deployment_group),
            ("inventory_source", self.inventory_source),
        ):
            _require_text(field_name, value)
        if self.inventory_timestamp.tzinfo is None or self.freshness_evaluated_at.tzinfo is None:
            raise ValueError("inventory timestamps must be timezone-aware")
        if self.freshness_max_age_hours < 1:
            raise ValueError("freshness_max_age_hours must be positive")

    def evaluated_freshness(self) -> FreshnessState:
        """Recalculate freshness at the recorded evaluation time."""
        return evaluate_freshness(
            inventory_timestamp=self.inventory_timestamp,
            evaluated_at=self.freshness_evaluated_at,
            max_age=timedelta(hours=self.freshness_max_age_hours),
        )

    def freshness_is_consistent(self) -> bool:
        """Return whether stored and deterministically evaluated freshness agree."""
        if self.freshness_state is FreshnessState.UNKNOWN:
            return False
        return self.freshness_state is self.evaluated_freshness()


def refresh_for_assessment(device: DeviceInventory, now: datetime) -> DeviceInventory:
    """Recompute freshness at assess time. A stale file cannot stay marked fresh."""
    state = evaluate_freshness(
        inventory_timestamp=device.inventory_timestamp,
        evaluated_at=now,
        max_age=timedelta(hours=device.freshness_max_age_hours),
    )
    return replace(device, freshness_state=state, freshness_evaluated_at=now)


def evaluate_freshness(
    *,
    inventory_timestamp: datetime,
    evaluated_at: datetime,
    max_age: timedelta,
) -> FreshnessState:
    """Classify inventory freshness without silently treating unknown data as current."""
    if inventory_timestamp.tzinfo is None or evaluated_at.tzinfo is None:
        return FreshnessState.UNKNOWN
    if max_age <= timedelta(0):
        raise ValueError("max_age must be positive")
    if inventory_timestamp > evaluated_at:
        return FreshnessState.UNKNOWN
    age = evaluated_at - inventory_timestamp
    return FreshnessState.FRESH if age <= max_age else FreshnessState.STALE


def _require_text(field_name: str, value: str) -> None:
    if not value.strip():
        raise ValueError(f"{field_name} must not be empty")


def _require_verified_version(
    verification_state: VerificationState,
    version: str | None,
    component_type: str,
) -> None:
    if verification_state is VerificationState.VERIFIED and not (version and version.strip()):
        raise ValueError(f"verified {component_type} requires a version")
