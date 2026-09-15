"""Numeric risk score contributions. Hard gates are applied separately."""

from __future__ import annotations

from findupdates.inventory.models import ClinicalCriticality, DeviceInventory, NetworkExposure
from findupdates.normalization.models import (
    CvssRecord,
    Exploitability,
    RebootRequirement,
    RemediationKind,
    TriState,
    UpdateAdvisory,
    UpdateCategory,
    VendorSeverity,
)
from findupdates.risk.models import PolicyDocument, ScoreContribution

_VENDOR = {
    VendorSeverity.NONE: 0.0,
    VendorSeverity.LOW: 0.25,
    VendorSeverity.MEDIUM: 0.5,
    VendorSeverity.HIGH: 0.75,
    VendorSeverity.CRITICAL: 1.0,
    VendorSeverity.UNKNOWN: 0.7,
}
_CLINICAL = {
    ClinicalCriticality.LOW: 0.2,
    ClinicalCriticality.MEDIUM: 0.5,
    ClinicalCriticality.HIGH: 0.8,
    ClinicalCriticality.CRITICAL: 1.0,
    ClinicalCriticality.UNKNOWN: 0.8,
}
_EXPOSURE = {
    NetworkExposure.ISOLATED: 0.1,
    NetworkExposure.RESTRICTED_LAN: 0.4,
    NetworkExposure.ENTERPRISE_LAN: 0.7,
    NetworkExposure.INTERNET_EXPOSED: 1.0,
    NetworkExposure.UNKNOWN: 0.7,
}
_FIRMWARE_CATEGORIES = {
    UpdateCategory.FIRMWARE,
    UpdateCategory.BIOS,
    UpdateCategory.MICROCODE,
}


def score_contributions(
    advisory: UpdateAdvisory, device: DeviceInventory, policy: PolicyDocument
) -> tuple[ScoreContribution, ...]:
    """Return every numeric contribution used to build the 0-100 score."""
    weights = policy.weights
    modifiers = policy.modifiers
    items: list[ScoreContribution] = []
    cvss_score = _best_cvss(advisory.cvss)
    if cvss_score is None:
        items.append(
            ScoreContribution(
                "MISSING_CVSS",
                0.0,
                "no CVSS base score available; score is not treated as proof of low risk",
            )
        )
    else:
        points = (cvss_score / 10.0) * weights.get("cvss", 0.0)
        items.append(ScoreContribution("CVSS", points, f"highest CVSS base score {cvss_score:.1f}"))
    vendor_points = _VENDOR[advisory.vendor_severity] * weights.get("vendor_severity", 0.0)
    items.append(
        ScoreContribution(
            "VENDOR_SEVERITY",
            vendor_points,
            f"vendor severity {advisory.vendor_severity.value}",
        )
    )
    clinical_points = _CLINICAL[device.clinical_criticality] * weights.get(
        "clinical_criticality", 0.0
    )
    items.append(
        ScoreContribution(
            "CLINICAL_CRITICALITY",
            clinical_points,
            f"clinical criticality {device.clinical_criticality.value}",
        )
    )
    exposure_points = _EXPOSURE[device.network_exposure] * weights.get("network_exposure", 0.0)
    items.append(
        ScoreContribution(
            "NETWORK_EXPOSURE",
            exposure_points,
            f"network exposure {device.network_exposure.value}",
        )
    )
    if advisory.known_exploited is TriState.TRUE:
        items.append(
            ScoreContribution("KEV", modifiers.get("kev", 0.0), "known exploitation asserted")
        )
    if advisory.exploitability is Exploitability.HIGH:
        items.append(
            ScoreContribution(
                "EXPLOITABILITY_HIGH",
                modifiers.get("exploitability_high", 0.0),
                "vendor/enrichment exploitability is high",
            )
        )
    if _network_no_auth(advisory.cvss):
        items.append(
            ScoreContribution(
                "NETWORK_NO_AUTH",
                modifiers.get("network_no_auth", 0.0),
                "CVSS vector indicates network attack vector with no privileges",
            )
        )
    if advisory.reboot_requirement is RebootRequirement.REQUIRED:
        items.append(
            ScoreContribution(
                "REBOOT_REQUIRED",
                modifiers.get("reboot_required", 0.0),
                "reboot is required",
            )
        )
    elif advisory.reboot_requirement is RebootRequirement.MAYBE:
        items.append(
            ScoreContribution(
                "REBOOT_REQUIRED",
                modifiers.get("reboot_required", 0.0) / 2.0,
                "reboot may be required",
            )
        )
    if advisory.update_category in _FIRMWARE_CATEGORIES:
        items.append(
            ScoreContribution(
                "FIRMWARE_OR_BIOS",
                modifiers.get("firmware_or_bios", 0.0),
                f"update category {advisory.update_category.value}",
            )
        )
    if advisory.known_issues:
        items.append(
            ScoreContribution(
                "KNOWN_ISSUES",
                modifiers.get("known_issues", 0.0),
                "advisory lists known compatibility issues",
            )
        )
    if _no_workaround(advisory):
        items.append(
            ScoreContribution(
                "NO_WORKAROUND",
                modifiers.get("no_workaround", 0.0),
                "no workaround or vendor fix is recorded",
            )
        )
    return tuple(items)


def clamp_score(contributions: tuple[ScoreContribution, ...], cap: int) -> int:
    """Sum contributions and clamp to 0-cap as an integer score."""
    total = sum(item.points for item in contributions)
    bounded = max(0.0, min(float(cap), total))
    return int(round(bounded))


def _best_cvss(records: tuple[CvssRecord, ...]) -> float | None:
    scores = [item.base_score for item in records if item.base_score is not None]
    return max(scores) if scores else None


def _network_no_auth(records: tuple[CvssRecord, ...]) -> bool:
    for record in records:
        vector = (record.vector or "").upper()
        if "AV:N" in vector and "PR:N" in vector:
            return True
    return False


def _no_workaround(advisory: UpdateAdvisory) -> bool:
    kinds = {item.kind for item in advisory.remediations}
    has_fix = RemediationKind.VENDOR_FIX in kinds or RemediationKind.WORKAROUND in kinds
    return not has_fix
