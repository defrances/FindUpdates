"""Hard policy gates that override numeric score."""

from __future__ import annotations

from findupdates.applicability.models import ApplicabilityResult, ApplicabilityVerdict
from findupdates.inventory.models import (
    ClinicalCriticality,
    DeviceInventory,
    FreshnessState,
    HardwareKind,
    NetworkExposure,
    VerificationState,
)
from findupdates.normalization.models import Confidence, UpdateAdvisory, UpdateCategory
from findupdates.risk.models import PolicyDocument, PolicyResult, RiskReason, stricter_result

_FIRMWARE_CATEGORIES = {
    UpdateCategory.FIRMWARE,
    UpdateCategory.BIOS,
    UpdateCategory.MICROCODE,
}

_CRITICAL_CLINICAL = {ClinicalCriticality.HIGH, ClinicalCriticality.CRITICAL}


def apply_hard_gates(
    *,
    advisory: UpdateAdvisory,
    device: DeviceInventory,
    applicability: ApplicabilityResult,
    policy: PolicyDocument,
    band_result: PolicyResult,
) -> tuple[PolicyResult, tuple[str, ...]]:
    """Return the stricter of score-derived policy and independent hard gates."""
    result = band_result
    applied: list[str] = []

    def _apply(code: RiskReason) -> None:
        nonlocal result
        gate = policy.hard_gates.get(code.value)
        if gate is None:
            return
        result = stricter_result(result, gate)
        applied.append(code.value)

    if applicability.verdict is ApplicabilityVerdict.UNKNOWN:
        _apply(RiskReason.UNKNOWN_APPLICABILITY)
    if applicability.verdict is ApplicabilityVerdict.POSSIBLY_AFFECTED:
        _apply(RiskReason.POSSIBLY_AFFECTED)
    if device.evaluated_freshness() is not FreshnessState.FRESH:
        _apply(RiskReason.STALE_INVENTORY)
    if device.clinical_criticality is ClinicalCriticality.UNKNOWN:
        _apply(RiskReason.UNKNOWN_CLINICAL_CRITICALITY)
    if device.network_exposure is NetworkExposure.UNKNOWN:
        _apply(RiskReason.UNKNOWN_NETWORK_EXPOSURE)
    if (
        advisory.update_category in _FIRMWARE_CATEGORIES
        and device.clinical_criticality in _CRITICAL_CLINICAL
        and not _oem_qualified(device, advisory.update_category)
    ):
        _apply(RiskReason.FIRMWARE_CRITICAL_UNKNOWN_OEM)
    if applicability.verdict is ApplicabilityVerdict.AFFECTED and applicability.confidence in {
        Confidence.LOW,
        Confidence.UNKNOWN,
    }:
        _apply(RiskReason.LOW_CONFIDENCE_AFFECTED)
    return result, tuple(dict.fromkeys(applied))


def _oem_qualified(device: DeviceInventory, category: UpdateCategory) -> bool:
    kinds = {
        UpdateCategory.BIOS: {HardwareKind.BIOS},
        UpdateCategory.FIRMWARE: {HardwareKind.FIRMWARE, HardwareKind.BIOS},
        UpdateCategory.MICROCODE: {HardwareKind.CPU},
    }.get(category, set())
    if not kinds:
        return True
    matching = [item for item in device.hardware_components if item.kind in kinds]
    if not matching:
        return False
    return any(item.verification_state is VerificationState.VERIFIED for item in matching)
