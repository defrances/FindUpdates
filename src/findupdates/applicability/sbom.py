"""SBOM CPE/PURL matching against advisory product identifiers."""

from __future__ import annotations

from findupdates.applicability.identity import classify_identity
from findupdates.applicability.models import IdentityStrength, MatchObservation, ReasonCode
from findupdates.applicability.version_status import inventory_version_relation
from findupdates.inventory.models import DeviceInventory, SoftwareComponent
from findupdates.normalization.models import AffectedProduct, UpdateAdvisory


def match_sbom_product(
    product: AffectedProduct,
    device: DeviceInventory,
    advisory: UpdateAdvisory,
) -> MatchObservation | None:
    """Match CPE/PURL/vendor product IDs on software components (SBOM-derived)."""
    best: MatchObservation | None = None
    for component in device.software_components:
        observation = _match_component(product, advisory, component)
        if observation is None:
            continue
        if best is None or _rank(observation) > _rank(best):
            best = observation
    return best


def _match_component(
    product: AffectedProduct,
    advisory: UpdateAdvisory,
    component: SoftwareComponent,
) -> MatchObservation | None:
    identifiers = component.identifiers
    if identifiers.purl and _purl_matches(product, identifiers.purl, component):
        identity = IdentityStrength.PURL
        codes: tuple[ReasonCode, ...] = (ReasonCode.PURL_MATCH,)
    else:
        identity, codes = classify_identity(
            product,
            vendor_product_id=identifiers.vendor_product_id,
            cpe=identifiers.cpe,
            purl=identifiers.purl,
            inventory_name=component.name,
        )
    if identity is IdentityStrength.NONE:
        return None
    relation, version_codes = inventory_version_relation(
        inventory_version=component.version,
        product=product,
        advisory=advisory,
    )
    inventory_fields = ["software_components.version"]
    if identifiers.vendor_product_id:
        inventory_fields.append("software_components.identifiers.vendor_product_id")
    if identifiers.cpe:
        inventory_fields.append("software_components.identifiers.cpe")
    if identifiers.purl:
        inventory_fields.append("software_components.identifiers.purl")
    source_fields = ["affected_products.status"]
    if product.vendor_product_id:
        source_fields.append("affected_products.vendor_product_id")
    if product.cpe:
        source_fields.append("affected_products.cpe")
    if product.version_range:
        source_fields.append("affected_products.version_range")
    return MatchObservation(
        matcher="sbom",
        identity=identity,
        version_relation=relation,
        architecture_match=None,
        reason_codes=tuple(dict.fromkeys((*codes, *version_codes))),
        source_fields=tuple(source_fields),
        inventory_fields=tuple(inventory_fields),
        detail=(
            f"sbom matcher identity={identity.value} component={component.name} "
            f"status={product.status.value} relation={relation}"
        ),
        product_status_value=product.status.value,
    )


def _purl_matches(product: AffectedProduct, purl: str, component: SoftwareComponent) -> bool:
    compacted_purl = _compact_identifier(purl)
    if (
        product.vendor_product_id
        and _compact_identifier(product.vendor_product_id) in compacted_purl
    ):
        return True
    return bool(
        product.cpe and component.identifiers.cpe and product.cpe == component.identifiers.cpe
    )


def _compact_identifier(value: str) -> str:
    return "".join(character for character in value.casefold() if character.isalnum())


def _rank(observation: MatchObservation) -> int:
    return {
        IdentityStrength.PRODUCT_ID: 4,
        IdentityStrength.CPE: 3,
        IdentityStrength.PURL: 3,
        IdentityStrength.FAMILY: 1,
        IdentityStrength.NONE: 0,
    }[observation.identity]
