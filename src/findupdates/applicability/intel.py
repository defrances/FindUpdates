"""Intel CPU, chipset, BIOS, firmware and driver matching."""

from __future__ import annotations

from collections.abc import Iterator

from findupdates.applicability.identity import architecture_constraint, classify_identity
from findupdates.applicability.models import IdentityStrength, MatchObservation, ReasonCode
from findupdates.applicability.version_status import inventory_version_relation
from findupdates.inventory.models import DeviceInventory, HardwareComponent, SoftwareComponent
from findupdates.normalization.models import AffectedProduct, UpdateAdvisory


def is_intel_product(product: AffectedProduct) -> bool:
    """Return whether this affected-product row describes an Intel component."""
    if product.vendor.strip().casefold() == "intel":
        return True
    return "intel" in product.product.casefold()


def match_intel_product(
    product: AffectedProduct,
    device: DeviceInventory,
    advisory: UpdateAdvisory,
) -> MatchObservation | None:
    """Match one affected-product row against Intel hardware/software inventory."""
    if not is_intel_product(product):
        return None
    best: MatchObservation | None = None
    for component, kind in _intel_surfaces(device):
        observation = _match_component(product, device, advisory, component, kind)
        if observation is None:
            continue
        if best is None or _rank(observation) > _rank(best):
            best = observation
    return best


def _intel_surfaces(
    device: DeviceInventory,
) -> Iterator[tuple[HardwareComponent | SoftwareComponent, str]]:
    for hardware in device.hardware_components:
        if _looks_intel(hardware.vendor, hardware.name):
            yield hardware, f"hardware_components.{hardware.kind.value}"
    for software in device.software_components:
        if _looks_intel(software.vendor, software.name):
            yield software, f"software_components.{software.kind.value}"


def _looks_intel(vendor: str, name: str) -> bool:
    return "intel" in vendor.casefold() or "intel" in name.casefold()


def _match_component(
    product: AffectedProduct,
    device: DeviceInventory,
    advisory: UpdateAdvisory,
    component: HardwareComponent | SoftwareComponent,
    inventory_kind: str,
) -> MatchObservation | None:
    identity, codes = classify_identity(
        product,
        vendor_product_id=component.identifiers.vendor_product_id,
        cpe=component.identifiers.cpe,
        purl=component.identifiers.purl,
        inventory_name=component.name,
    )
    if identity is IdentityStrength.NONE:
        return None
    arch = architecture_constraint(product.architectures, device.os.architecture)
    relation, version_codes = inventory_version_relation(
        inventory_version=component.version,
        product=product,
        advisory=advisory,
    )
    reasons = list(codes)
    reasons.extend(version_codes)
    if arch is False:
        reasons.append(ReasonCode.ARCHITECTURE_MISMATCH)
    source_fields = ["affected_products.product", "affected_products.status"]
    if product.vendor_product_id:
        source_fields.append("affected_products.vendor_product_id")
    if product.cpe:
        source_fields.append("affected_products.cpe")
    if product.version_range:
        source_fields.append("affected_products.version_range")
    inventory_fields = [f"{inventory_kind}.name", f"{inventory_kind}.version"]
    if component.identifiers.vendor_product_id:
        inventory_fields.append(f"{inventory_kind}.identifiers.vendor_product_id")
    if component.identifiers.cpe:
        inventory_fields.append(f"{inventory_kind}.identifiers.cpe")
    return MatchObservation(
        matcher="intel",
        identity=identity,
        version_relation=relation,
        architecture_match=arch,
        reason_codes=tuple(dict.fromkeys(reasons)),
        source_fields=tuple(source_fields),
        inventory_fields=tuple(inventory_fields),
        detail=(
            f"intel matcher identity={identity.value} component={component.name} "
            f"status={product.status.value} relation={relation}"
        ),
        product_status_value=product.status.value,
    )


def _rank(observation: MatchObservation) -> tuple[int, int]:
    identity_rank = {
        IdentityStrength.PRODUCT_ID: 4,
        IdentityStrength.CPE: 3,
        IdentityStrength.PURL: 3,
        IdentityStrength.FAMILY: 1,
        IdentityStrength.NONE: 0,
    }[observation.identity]
    return identity_rank, len(observation.reason_codes)
