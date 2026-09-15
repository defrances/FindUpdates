"""Compare inventory versions against advisory product constraints."""

from __future__ import annotations

from findupdates.applicability.models import ReasonCode, VersionRelation
from findupdates.applicability.versions import (
    compare_versions,
    compare_windows_versions,
    same_windows_build_family,
    version_in_range,
)
from findupdates.normalization.models import AffectedProduct, RemediationKind, UpdateAdvisory


def inventory_version_relation(
    *,
    inventory_version: str | None,
    product: AffectedProduct,
    advisory: UpdateAdvisory,
    treat_builds_as_windows_family: bool = False,
) -> tuple[VersionRelation, tuple[ReasonCode, ...]]:
    """Classify how an inventory version relates to a product row."""
    if inventory_version is None or not inventory_version.strip():
        return VersionRelation.MISSING, (ReasonCode.MISSING_VERSION,)
    version = inventory_version.strip()
    compare = compare_windows_versions if treat_builds_as_windows_family else compare_versions
    if product.version_range:
        try:
            if version_in_range(
                version, product.version_range, windows=treat_builds_as_windows_family
            ):
                return VersionRelation.IN_RANGE, (ReasonCode.VERSION_IN_RANGE,)
            return VersionRelation.OUT_OF_RANGE, (ReasonCode.VERSION_OUT_OF_RANGE,)
        except ValueError:
            return VersionRelation.UNPARSED, (ReasonCode.ADVISORY_INCOMPLETE,)
    fixed = _fixed_versions(advisory, product)
    if fixed:
        try:
            if any(compare(version, item) >= 0 for item in fixed):
                return VersionRelation.AT_OR_ABOVE_FIXED, (ReasonCode.VENDOR_FIXED,)
            return VersionRelation.BELOW_FIXED, (ReasonCode.VERSION_IN_RANGE,)
        except ValueError:
            return VersionRelation.UNPARSED, (ReasonCode.ADVISORY_INCOMPLETE,)
    if product.builds:
        if treat_builds_as_windows_family and any(
            same_windows_build_family(version, item) for item in product.builds
        ):
            return VersionRelation.IN_RANGE, (ReasonCode.VERSION_IN_RANGE,)
        try:
            if any(compare_versions(version, item) == 0 for item in product.builds):
                return VersionRelation.IN_RANGE, (ReasonCode.VERSION_IN_RANGE,)
        except ValueError:
            return VersionRelation.UNPARSED, (ReasonCode.ADVISORY_INCOMPLETE,)
        return VersionRelation.UNPARSED, (ReasonCode.ADVISORY_INCOMPLETE,)
    return VersionRelation.NOT_APPLICABLE, ()


def _fixed_versions(advisory: UpdateAdvisory, _product: AffectedProduct) -> tuple[str, ...]:
    found: list[str] = []
    for item in advisory.remediations:
        if item.kind is not RemediationKind.VENDOR_FIX:
            continue
        if item.fixed_version:
            found.append(item.fixed_version)
    return tuple(dict.fromkeys(found))
