"""Parse Intel CSAF 2.0 documents into canonical source records."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from findupdates.collectors.jsonutil import (
    list_of,
    mapping,
    parse_datetime,
    pick,
    sha256_json,
    text_of,
)
from findupdates.normalization.models import (
    AffectedProduct,
    Architecture,
    Confidence,
    CvssRecord,
    CvssVersion,
    Exploitability,
    FieldProvenance,
    NormalizedSourceRecord,
    ProductStatus,
    Provenance,
    RebootRequirement,
    Remediation,
    RemediationKind,
    TriState,
    UpdateCategory,
    Vendor,
    VendorSeverity,
)

PARSER_VERSION = "intel-csaf-1.0"
SOURCE = "intel-csaf"

_STATUS_FIELDS: tuple[tuple[str, ProductStatus], ...] = (
    ("known_affected", ProductStatus.AFFECTED),
    ("first_affected", ProductStatus.AFFECTED),
    ("known_not_affected", ProductStatus.NOT_AFFECTED),
    ("fixed", ProductStatus.FIXED),
    ("first_fixed", ProductStatus.FIXED),
    ("under_investigation", ProductStatus.UNKNOWN),
    ("recommended", ProductStatus.UNKNOWN),
)


def parse_csaf_document(
    document: Mapping[str, Any],
    *,
    source_url: str,
    retrieved_at: datetime,
) -> NormalizedSourceRecord:
    """Parse one CSAF security advisory.

    The record describes Intel component impact only. It is not authorization to
    install a generic Intel firmware/BIOS package on a medical device.
    """
    doc = mapping(pick(document, "document")) or {}
    tracking = mapping(pick(doc, "tracking")) or {}
    advisory_id = text_of(pick(tracking, "id"))
    title = text_of(pick(doc, "title"))
    if not advisory_id or not title:
        raise ValueError("CSAF document requires tracking.id and document.title")
    published_at = parse_datetime(pick(tracking, "initial_release_date")) or retrieved_at
    revised_at = parse_datetime(pick(tracking, "current_release_date"))
    products = _product_index(mapping(pick(document, "product_tree")))
    vulns = [node for item in list_of(pick(document, "vulnerabilities")) if (node := mapping(item))]
    cve_ids = _cve_ids(vulns)
    affected = _affected_products(vulns, products)
    cvss = _cvss(vulns)
    remediations = _remediations(vulns)
    references = _references(doc, source_url)
    category = _category(title, affected)
    return NormalizedSourceRecord(
        vendor=Vendor.INTEL,
        source=SOURCE,
        vendor_advisory_id=advisory_id,
        title=title,
        description=_aggregate_notes(doc, vulns),
        published_at=published_at,
        revised_at=revised_at,
        collected_at=retrieved_at,
        parser_version=PARSER_VERSION,
        provenance=Provenance(
            source_url=source_url,
            raw_sha256=sha256_json(dict(document)),
            retrieved_at=retrieved_at,
            content_type="application/json",
        ),
        cve_ids=cve_ids,
        package_ids=(),
        references=references,
        vendor_severity=_severity(cvss, vulns),
        cvss=cvss,
        update_category=category,
        reboot_requirement=RebootRequirement.UNKNOWN,
        known_exploited=TriState.UNKNOWN,
        exploitability=Exploitability.UNKNOWN,
        affected_products=affected,
        remediations=remediations,
        vendor_recommendation=None,
        field_provenance=(
            FieldProvenance("vendor_advisory_id", SOURCE),
            FieldProvenance("affected_products", SOURCE),
            FieldProvenance("known_exploited", SOURCE),
        ),
        normalization_confidence=Confidence.MEDIUM if affected else Confidence.LOW,
    )


def _product_index(tree: Mapping[str, Any] | None) -> dict[str, tuple[str, str | None]]:
    index: dict[str, tuple[str, str | None]] = {}
    if tree is None:
        return index
    for item in list_of(pick(tree, "full_product_names")):
        _index_product(index, mapping(item))
    _walk_branches(index, list_of(pick(tree, "branches")))
    return index


def _walk_branches(index: dict[str, tuple[str, str | None]], branches: list[Any]) -> None:
    for item in branches:
        node = mapping(item)
        if node is None:
            continue
        _index_product(index, mapping(pick(node, "product")))
        _walk_branches(index, list_of(pick(node, "branches")))


def _index_product(
    index: dict[str, tuple[str, str | None]], product: Mapping[str, Any] | None
) -> None:
    if product is None:
        return
    product_id = text_of(pick(product, "product_id"))
    name = text_of(pick(product, "name"))
    if not product_id or not name:
        return
    helper = mapping(pick(product, "product_identification_helper")) or {}
    cpe = text_of(pick(helper, "cpe"))
    index[product_id] = (name, cpe)


def _affected_products(
    vulns: list[Mapping[str, Any]],
    products: dict[str, tuple[str, str | None]],
) -> tuple[AffectedProduct, ...]:
    found: dict[tuple[str, str], AffectedProduct] = {}
    for vuln in vulns:
        status_node = mapping(pick(vuln, "product_status")) or {}
        for field_name, status in _STATUS_FIELDS:
            for product_id in list_of(pick(status_node, field_name)):
                identifier = text_of(product_id)
                if not identifier:
                    continue
                name, cpe = products.get(identifier, (identifier, None))
                found[(identifier, status.value)] = AffectedProduct(
                    vendor="intel",
                    product=name,
                    version_range=None,
                    builds=(),
                    architectures=_architectures(name, cpe),
                    vendor_product_id=identifier,
                    cpe=cpe,
                    status=status,
                )
    return tuple(found[key] for key in sorted(found))


def _cvss(vulns: list[Mapping[str, Any]]) -> tuple[CvssRecord, ...]:
    records: dict[tuple[str, str | None, str], CvssRecord] = {}
    for vuln in vulns:
        for item in list_of(pick(vuln, "scores")):
            node = mapping(item)
            if node is None:
                continue
            for key, version in (
                ("cvss_v4", CvssVersion.V4_0),
                ("cvss_v3", CvssVersion.V3_1),
                ("cvss_v2", CvssVersion.V2_0),
            ):
                score = mapping(pick(node, key))
                if score is None:
                    continue
                vector = text_of(pick(score, "vectorString", "vector"))
                raw_version = text_of(pick(score, "version"))
                parsed_version = _cvss_version(raw_version, version, vector)
                base = pick(score, "baseScore")
                base_score = float(base) if isinstance(base, int | float) else None
                record = CvssRecord(parsed_version, vector, base_score, SOURCE)
                records[(record.version.value, record.vector, record.source)] = record
    return tuple(records[key] for key in sorted(records))


def _cvss_version(raw: str | None, fallback: CvssVersion, vector: str | None) -> CvssVersion:
    if raw == "4.0" or (vector and vector.startswith("CVSS:4.0")):
        return CvssVersion.V4_0
    if raw == "3.1" or (vector and vector.startswith("CVSS:3.1")):
        return CvssVersion.V3_1
    if raw == "3.0" or (vector and vector.startswith("CVSS:3.0")):
        return CvssVersion.V3_0
    if raw in {"2.0", "2"} or (vector and vector.startswith("CVSS:2")):
        return CvssVersion.V2_0
    return fallback


def _severity(cvss: tuple[CvssRecord, ...], vulns: list[Mapping[str, Any]]) -> VendorSeverity:
    labels: list[str] = []
    for vuln in vulns:
        for item in list_of(pick(vuln, "scores")):
            node = mapping(item)
            if node is None:
                continue
            for key in ("cvss_v4", "cvss_v3", "cvss_v2"):
                score = mapping(pick(node, key))
                if score is None:
                    continue
                label = text_of(pick(score, "baseSeverity"))
                if label:
                    labels.append(label.lower())
    if "critical" in labels:
        return VendorSeverity.CRITICAL
    if "high" in labels:
        return VendorSeverity.HIGH
    if "medium" in labels:
        return VendorSeverity.MEDIUM
    if "low" in labels:
        return VendorSeverity.LOW
    if "none" in labels:
        return VendorSeverity.NONE
    if not cvss:
        return VendorSeverity.UNKNOWN
    best = max((item.base_score or -1) for item in cvss)
    if best >= 9:
        return VendorSeverity.CRITICAL
    if best >= 7:
        return VendorSeverity.HIGH
    if best >= 4:
        return VendorSeverity.MEDIUM
    if best >= 0:
        return VendorSeverity.LOW
    return VendorSeverity.UNKNOWN


def _remediations(vulns: list[Mapping[str, Any]]) -> tuple[Remediation, ...]:
    remediations: list[Remediation] = []
    for vuln in vulns:
        for item in list_of(pick(vuln, "remediations")):
            node = mapping(item)
            if node is None:
                continue
            category = (text_of(pick(node, "category")) or "unknown").lower()
            kind = {
                "vendor_fix": RemediationKind.VENDOR_FIX,
                "workaround": RemediationKind.WORKAROUND,
                "mitigation": RemediationKind.MITIGATION,
                "none_available": RemediationKind.UNAVAILABLE,
                "no_fix_planned": RemediationKind.UNAVAILABLE,
            }.get(category, RemediationKind.UNKNOWN)
            remediations.append(
                Remediation(
                    kind=kind,
                    description=text_of(pick(node, "details")),
                    fixed_version=None,
                    package_id=None,
                )
            )
    return tuple(remediations)


def _references(doc: Mapping[str, Any], source_url: str) -> tuple[str, ...]:
    urls = [source_url]
    for item in list_of(pick(doc, "references")):
        node = mapping(item)
        if node is None:
            continue
        url = text_of(pick(node, "url"))
        if url:
            urls.append(url)
    return tuple(dict.fromkeys(urls))


def _aggregate_notes(doc: Mapping[str, Any], vulns: list[Mapping[str, Any]]) -> str | None:
    notes: list[str] = []
    for item in list_of(pick(doc, "notes")):
        node = mapping(item)
        text = text_of(pick(node, "text")) if node else None
        if text:
            notes.append(text)
    for vuln in vulns:
        for item in list_of(pick(vuln, "notes")):
            node = mapping(item)
            text = text_of(pick(node, "text")) if node else None
            if text:
                notes.append(text)
    return " ".join(notes) if notes else None


def _category(title: str, products: tuple[AffectedProduct, ...]) -> UpdateCategory:
    haystack = " ".join((title, *(item.product for item in products))).lower()
    if "microcode" in haystack:
        return UpdateCategory.MICROCODE
    if "bios" in haystack or "uefi" in haystack:
        return UpdateCategory.BIOS
    if "firmware" in haystack:
        return UpdateCategory.FIRMWARE
    if "driver" in haystack:
        return UpdateCategory.DRIVER
    if "core" in haystack or "processor" in haystack or "cpu" in haystack:
        return UpdateCategory.MICROCODE
    return UpdateCategory.UNKNOWN


def _architectures(name: str, cpe: str | None) -> tuple[Architecture, ...]:
    haystack = f"{name} {cpe or ''}".lower()
    if "arm64" in haystack:
        return (Architecture.ARM64,)
    if "x86" in haystack:
        return (Architecture.X86,)
    return (Architecture.X64,) if "x64" in haystack else (Architecture.UNKNOWN,)


def _cve_ids(vulns: list[Mapping[str, Any]]) -> tuple[str, ...]:
    found: list[str] = []
    for item in vulns:
        raw = text_of(pick(item, "cve"))
        if raw and raw.startswith("CVE-"):
            found.append(raw)
    return tuple(sorted(set(found)))
