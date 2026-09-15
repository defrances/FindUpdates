"""Shared identifier and name matching used by vendor-specific matchers."""

from __future__ import annotations

import re

from findupdates.applicability.models import IdentityStrength, ReasonCode
from findupdates.normalization.models import AffectedProduct, Architecture

_NAME_NOISE = re.compile(r"[^a-z0-9]+")


def normalize_name(value: str) -> str:
    """Collapse a product name to lowercase alphanumeric tokens."""
    return _NAME_NOISE.sub(" ", value.casefold()).strip()


def names_family_match(advisory_name: str, inventory_name: str) -> bool:
    """Return whether two names describe the same product family.

    Substring inclusion is intentionally conservative and never sufficient on its
    own for a `not_affected` conclusion.
    """
    left = normalize_name(advisory_name)
    right = normalize_name(inventory_name)
    if not left or not right:
        return False
    return left == right or left in right or right in left


def equal_text(left: str | None, right: str | None) -> bool:
    """Case-insensitive equality that treats blank values as unmatched."""
    if left is None or right is None:
        return False
    stripped_left, stripped_right = left.strip(), right.strip()
    if not stripped_left or not stripped_right:
        return False
    return stripped_left.casefold() == stripped_right.casefold()


def cpe_product_key(cpe: str | None) -> tuple[str, str] | None:
    """Return (vendor, product) from a CPE 2.3 string when present."""
    if cpe is None or not cpe.strip():
        return None
    parts = cpe.split(":")
    if len(parts) < 5:
        return None
    vendor, product = parts[3].casefold(), parts[4].casefold()
    if not vendor or not product or vendor == "*" or product == "*":
        return None
    return vendor, product


def architecture_constraint(
    product_archs: tuple[Architecture, ...], inventory_arch: str | None
) -> bool | None:
    """Return True/False when both sides assert an architecture, else None."""
    if not product_archs:
        return None
    asserted = {item.value for item in product_archs if item is not Architecture.UNKNOWN}
    if not asserted:
        return None
    if inventory_arch is None or not inventory_arch.strip():
        return None
    normalized = inventory_arch.strip().casefold()
    if normalized == Architecture.UNKNOWN.value:
        return None
    return normalized in asserted


def classify_identity(
    product: AffectedProduct,
    *,
    vendor_product_id: str | None,
    cpe: str | None,
    purl: str | None,
    inventory_name: str | None,
) -> tuple[IdentityStrength, tuple[ReasonCode, ...]]:
    """Rank the strongest deterministic identity match for one inventory surface."""
    del purl
    if equal_text(product.vendor_product_id, vendor_product_id):
        return IdentityStrength.PRODUCT_ID, (ReasonCode.PRODUCT_ID_MATCH,)
    if equal_text(product.cpe, cpe) or (
        cpe_product_key(product.cpe) is not None
        and cpe_product_key(product.cpe) == cpe_product_key(cpe)
    ):
        return IdentityStrength.CPE, (ReasonCode.CPE_MATCH,)
    if inventory_name and names_family_match(product.product, inventory_name):
        return IdentityStrength.FAMILY, (ReasonCode.PRODUCT_FAMILY_MATCH,)
    return IdentityStrength.NONE, ()
