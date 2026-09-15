"""Windows OS product/build/architecture matching."""

from __future__ import annotations

from findupdates.applicability.identity import architecture_constraint, classify_identity
from findupdates.applicability.models import IdentityStrength, MatchObservation, ReasonCode
from findupdates.applicability.version_status import inventory_version_relation
from findupdates.inventory.models import DeviceInventory
from findupdates.normalization.models import AffectedProduct, UpdateAdvisory


def is_windows_product(product: AffectedProduct) -> bool:
    """Return whether this affected-product row describes a Windows SKU."""
    if product.vendor.strip().casefold() == "microsoft":
        return True
    return "windows" in product.product.casefold()


def match_windows_product(
    product: AffectedProduct,
    device: DeviceInventory,
    advisory: UpdateAdvisory,
) -> MatchObservation | None:
    """Match one affected-product row against the device operating system."""
    if not is_windows_product(product):
        return None
    os_record = device.os
    identity, codes = classify_identity(
        product,
        vendor_product_id=os_record.vendor_product_id,
        cpe=os_record.cpe,
        purl=None,
        inventory_name=os_record.product,
    )
    if identity is IdentityStrength.NONE and os_record.edition:
        identity, codes = classify_identity(
            product,
            vendor_product_id=os_record.vendor_product_id,
            cpe=os_record.cpe,
            purl=None,
            inventory_name=f"{os_record.product} {os_record.edition}",
        )
    if identity is IdentityStrength.NONE:
        return None
    arch = architecture_constraint(product.architectures, os_record.architecture)
    inventory_version = os_record.build or os_record.version
    relation, version_codes = inventory_version_relation(
        inventory_version=inventory_version,
        product=product,
        advisory=advisory,
        treat_builds_as_windows_family=True,
    )
    reasons = list(codes)
    reasons.extend(version_codes)
    if product.status.value == "not_affected":
        reasons.append(ReasonCode.VENDOR_NOT_AFFECTED)
    elif product.status.value == "affected":
        reasons.append(ReasonCode.VENDOR_AFFECTED)
    if arch is False:
        reasons.append(ReasonCode.ARCHITECTURE_MISMATCH)
    source_fields = _source_fields(product, advisory)
    inventory_fields = ["os.product", "os.architecture"]
    if os_record.vendor_product_id:
        inventory_fields.append("os.vendor_product_id")
    if os_record.cpe:
        inventory_fields.append("os.cpe")
    if os_record.build:
        inventory_fields.append("os.build")
    elif os_record.version:
        inventory_fields.append("os.version")
    return MatchObservation(
        matcher="windows",
        identity=identity,
        version_relation=relation,
        architecture_match=arch,
        reason_codes=tuple(dict.fromkeys(reasons)),
        source_fields=source_fields,
        inventory_fields=tuple(inventory_fields),
        detail=_detail(product, identity, relation, arch, inventory_version),
        product_status_value=product.status.value,
    )


def _source_fields(product: AffectedProduct, advisory: UpdateAdvisory) -> tuple[str, ...]:
    fields = ["affected_products.product", "affected_products.status"]
    if product.vendor_product_id:
        fields.append("affected_products.vendor_product_id")
    if product.cpe:
        fields.append("affected_products.cpe")
    if product.version_range:
        fields.append("affected_products.version_range")
    if product.builds:
        fields.append("affected_products.builds")
    if product.architectures:
        fields.append("affected_products.architectures")
    if any(item.fixed_version for item in advisory.remediations):
        fields.append("remediations.fixed_version")
    return tuple(fields)


def _detail(
    product: AffectedProduct,
    identity: IdentityStrength,
    relation: object,
    arch: bool | None,
    inventory_version: str | None,
) -> str:
    arch_text = "unconstrained" if arch is None else str(arch).lower()
    version_text = inventory_version or "missing"
    return (
        f"windows matcher identity={identity.value} status={product.status.value} "
        f"version={version_text} relation={relation} architecture_match={arch_text}"
    )
