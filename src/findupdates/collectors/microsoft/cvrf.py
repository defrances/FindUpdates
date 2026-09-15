"""Parse MSRC CVRF JSON into canonical source records."""

from __future__ import annotations

import re
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
    PackageId,
    PackageKind,
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

PARSER_VERSION = "msrc-cvrf-1.0"
SOURCE = "msrc"

_THREAT_IMPACT = 0
_THREAT_EXPLOIT = 1
_THREAT_SEVERITY = 3
_REMEDIATION_WORKAROUND = 0
_REMEDIATION_MITIGATION = 1
_REMEDIATION_KB = 2
_REMEDIATION_KNOWN_ISSUE = 5
_PRODUCT_KNOWN_AFFECTED = 3

_HTML_TAG = re.compile(r"<[^>]+>")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def parse_cvrf_document(
    document: Mapping[str, Any],
    *,
    source_url: str,
    retrieved_at: datetime,
    document_sha256: str,
    content_type: str = "application/json",
) -> tuple[list[NormalizedSourceRecord], list[str]]:
    """Parse each CVRF vulnerability independently.

    A malformed vulnerability is reported and skipped so the rest of the batch survives.
    """
    del document_sha256
    tracking = mapping(pick(document, "DocumentTracking")) or {}
    identification = mapping(pick(tracking, "Identification")) or {}
    document_id = text_of(pick(identification, "ID")) or "unknown-document"
    published_at = parse_datetime(pick(tracking, "InitialReleaseDate")) or retrieved_at
    products = _product_index(mapping(pick(document, "ProductTree")))

    records: list[NormalizedSourceRecord] = []
    errors: list[str] = []
    for index, raw_item in enumerate(list_of(pick(document, "Vulnerability"))):
        vulnerability = mapping(raw_item)
        if vulnerability is None:
            errors.append(f"{document_id}[{index}]: vulnerability node is not an object")
            continue
        try:
            records.append(
                _parse_vulnerability(
                    vulnerability,
                    document_id=document_id,
                    published_at=published_at,
                    retrieved_at=retrieved_at,
                    source_url=source_url,
                    products=products,
                    content_type=content_type,
                )
            )
        except (TypeError, ValueError, KeyError) as exc:
            identifier = text_of(pick(vulnerability, "CVE")) or f"ordinal-{index}"
            errors.append(f"{document_id}/{identifier}: {exc}")
    return records, errors


def _parse_vulnerability(
    vulnerability: Mapping[str, Any],
    *,
    document_id: str,
    published_at: datetime,
    retrieved_at: datetime,
    source_url: str,
    products: dict[str, tuple[str, str | None]],
    content_type: str,
) -> NormalizedSourceRecord:
    title = text_of(pick(vulnerability, "Title"))
    if title is None:
        raise ValueError("missing title")
    cve = _cve_id(text_of(pick(vulnerability, "CVE")))
    vendor_advisory_id = cve or f"{document_id}:{pick(vulnerability, 'Ordinal') or 'unknown'}"
    description = _first_note(vulnerability, note_type=2)
    kb_packages, remediations, supersedes, known_issues, reboot = _remediations(vulnerability)
    affected = _affected_products(
        vulnerability, products, remediations_fixed=_fixed_builds(vulnerability)
    )
    severity = _severity(vulnerability)
    cvss = _cvss(vulnerability)
    exploited, exploitability = _exploitation(vulnerability)
    references = _references(vulnerability, cve)
    own_published, own_revised = _vulnerability_dates(vulnerability)
    provenance = Provenance(
        source_url=source_url,
        raw_sha256=sha256_json(dict(vulnerability)),
        retrieved_at=retrieved_at,
        content_type=content_type,
    )
    return NormalizedSourceRecord(
        vendor=Vendor.MICROSOFT,
        source=SOURCE,
        vendor_advisory_id=vendor_advisory_id,
        title=_strip_markup(title),
        description=_strip_markup(description) if description else None,
        published_at=own_published or published_at,
        revised_at=own_revised or own_published,
        collected_at=retrieved_at,
        parser_version=PARSER_VERSION,
        provenance=provenance,
        cve_ids=(cve,) if cve else (),
        package_ids=kb_packages,
        references=references,
        vendor_severity=severity,
        cvss=cvss,
        update_category=_category(title, affected),
        reboot_requirement=reboot,
        known_exploited=exploited,
        exploitability=exploitability,
        affected_products=affected,
        remediations=remediations,
        supersedes=supersedes,
        known_issues=known_issues,
        field_provenance=(
            FieldProvenance("vendor_advisory_id", SOURCE),
            FieldProvenance("package_ids", SOURCE),
            FieldProvenance("reboot_requirement", SOURCE),
            FieldProvenance("known_exploited", SOURCE),
        ),
        normalization_confidence=Confidence.MEDIUM,
    )


def _vulnerability_dates(
    vulnerability: Mapping[str, Any],
) -> tuple[datetime | None, datetime | None]:
    """Own CVE dates only. Sentinel ReleaseDate and Specified=false are missing."""
    published = _field_datetime(vulnerability, "ReleaseDate")
    revised = _field_datetime(vulnerability, "RevisionDate") or _field_datetime(
        vulnerability, "CurrentReleaseDate"
    )
    history = _revision_history_dates(vulnerability)
    if published is None and history:
        published = min(history)
    if revised is None and history:
        revised = max(history)
    return published, revised


def _field_datetime(node: Mapping[str, Any], field: str) -> datetime | None:
    if not _field_specified(node, field):
        return None
    return parse_datetime(pick(node, field))


def _field_specified(node: Mapping[str, Any], field: str) -> bool:
    flag = pick(node, f"{field}Specified")
    if flag is None:
        return True
    if isinstance(flag, bool):
        return flag
    text = text_of(flag)
    if text is None:
        return True
    return text.casefold() not in {"false", "0", "no"}


def _revision_history_dates(vulnerability: Mapping[str, Any]) -> list[datetime]:
    dates: list[datetime] = []
    for item in list_of(pick(vulnerability, "RevisionHistory")):
        entry = mapping(item)
        if entry is None:
            continue
        parsed = parse_datetime(pick(entry, "Date"))
        if parsed is not None:
            dates.append(parsed)
    return dates


def _product_index(tree: Mapping[str, Any] | None) -> dict[str, tuple[str, str | None]]:
    index: dict[str, tuple[str, str | None]] = {}
    if tree is None:
        return index
    for item in list_of(pick(tree, "FullProductName")):
        node = mapping(item)
        if node is None:
            continue
        product_id = text_of(pick(node, "ProductID"))
        name = text_of(pick(node, "Value")) or text_of(pick(node, "Name"))
        if product_id and name:
            index[product_id] = (name, text_of(pick(node, "CPE")))
    return index


def _affected_products(
    vulnerability: Mapping[str, Any],
    products: dict[str, tuple[str, str | None]],
    remediations_fixed: dict[str, str],
) -> tuple[AffectedProduct, ...]:
    affected: list[AffectedProduct] = []
    for status_node in list_of(pick(vulnerability, "ProductStatuses")):
        node = mapping(status_node)
        if node is None:
            continue
        status = _product_status(pick(node, "Type"), text_of(pick(node, "Status")))
        for product_id in list_of(pick(node, "ProductID")):
            identifier = text_of(product_id)
            if not identifier:
                continue
            name, cpe = products.get(identifier, (identifier, None))
            fixed = remediations_fixed.get(identifier)
            affected.append(
                AffectedProduct(
                    vendor="microsoft",
                    product=name,
                    version_range=None,
                    builds=(fixed,) if fixed else (),
                    architectures=_architectures(name, cpe),
                    vendor_product_id=identifier,
                    cpe=cpe,
                    status=status,
                )
            )
    return tuple(affected)


def _product_status(type_value: object, status_text: str | None) -> ProductStatus:
    if status_text:
        normalized = status_text.strip().lower()
        if "not affected" in normalized:
            return ProductStatus.NOT_AFFECTED
        if "fixed" in normalized:
            return ProductStatus.FIXED
        if "affected" in normalized:
            return ProductStatus.AFFECTED
    if type_value == _PRODUCT_KNOWN_AFFECTED:
        return ProductStatus.AFFECTED
    return ProductStatus.UNKNOWN


def _remediations(
    vulnerability: Mapping[str, Any],
) -> tuple[
    tuple[PackageId, ...],
    tuple[Remediation, ...],
    tuple[str, ...],
    tuple[str, ...],
    RebootRequirement,
]:
    packages: list[PackageId] = []
    remediations: list[Remediation] = []
    supersedes: list[str] = []
    known_issues: list[str] = []
    restarts: set[str] = set()
    for item in list_of(pick(vulnerability, "Remediations")):
        node = mapping(item)
        if node is None:
            continue
        remediation_type = pick(node, "Type")
        description = text_of(pick(node, "Description"))
        restart = text_of(mapping(pick(node, "RestartRequired")) or pick(node, "RestartRequired"))
        if restart:
            restarts.add(restart.strip().lower())
        supercedence = text_of(pick(node, "Supercedence"))
        if supercedence:
            supersedes.append(
                supercedence if supercedence.upper().startswith("KB") else f"KB{supercedence}"
            )
        if remediation_type == _REMEDIATION_KB and description:
            kb = description if description.upper().startswith("KB") else f"KB{description}"
            package = PackageId(PackageKind.KB, kb)
            packages.append(package)
            remediations.append(
                Remediation(
                    kind=RemediationKind.VENDOR_FIX,
                    description=text_of(pick(node, "SubType")) or kb,
                    fixed_version=text_of(pick(node, "FixedBuild")),
                    package_id=package,
                )
            )
        elif remediation_type == _REMEDIATION_WORKAROUND and description:
            remediations.append(
                Remediation(RemediationKind.WORKAROUND, _strip_markup(description), None, None)
            )
        elif remediation_type == _REMEDIATION_MITIGATION and description:
            remediations.append(
                Remediation(RemediationKind.MITIGATION, _strip_markup(description), None, None)
            )
        elif remediation_type == _REMEDIATION_KNOWN_ISSUE and description:
            known_issues.append(_strip_markup(description))
    unique_packages = tuple({(item.kind, item.value): item for item in packages}.values())
    return (
        unique_packages,
        tuple(remediations),
        tuple(dict.fromkeys(supersedes)),
        tuple(dict.fromkeys(known_issues)),
        _reboot(restarts),
    )


def _fixed_builds(vulnerability: Mapping[str, Any]) -> dict[str, str]:
    builds: dict[str, str] = {}
    for item in list_of(pick(vulnerability, "Remediations")):
        node = mapping(item)
        if node is None:
            continue
        fixed = text_of(pick(node, "FixedBuild"))
        if not fixed:
            continue
        for product_id in list_of(pick(node, "ProductID")):
            identifier = text_of(product_id)
            if identifier:
                builds[identifier] = fixed
    return builds


def _reboot(values: set[str]) -> RebootRequirement:
    normalized = {value for value in values if value}
    if not normalized:
        return RebootRequirement.UNKNOWN
    if normalized == {"yes"}:
        return RebootRequirement.REQUIRED
    if normalized == {"no"}:
        return RebootRequirement.NO
    if normalized == {"maybe"}:
        return RebootRequirement.MAYBE
    if normalized <= {"yes", "maybe"}:
        return RebootRequirement.REQUIRED
    if normalized <= {"no", "maybe"}:
        return RebootRequirement.MAYBE
    return RebootRequirement.UNKNOWN


def _severity(vulnerability: Mapping[str, Any]) -> VendorSeverity:
    labels: list[str] = []
    for item in list_of(pick(vulnerability, "Threats")):
        node = mapping(item)
        if node is None or pick(node, "Type") != _THREAT_SEVERITY:
            continue
        label = text_of(pick(node, "Description"))
        if label:
            labels.append(label.strip().lower())
    if "critical" in labels:
        return VendorSeverity.CRITICAL
    if "important" in labels:
        return VendorSeverity.HIGH
    if "moderate" in labels:
        return VendorSeverity.MEDIUM
    if "low" in labels:
        return VendorSeverity.LOW
    if "none" in labels:
        return VendorSeverity.NONE
    return VendorSeverity.UNKNOWN


def _cvss(vulnerability: Mapping[str, Any]) -> tuple[CvssRecord, ...]:
    records: list[CvssRecord] = []
    seen: set[tuple[str, str | None]] = set()
    for item in list_of(pick(vulnerability, "CVSSScoreSets")):
        node = mapping(item)
        if node is None:
            continue
        vector = text_of(pick(node, "Vector"))
        score = pick(node, "BaseScore")
        base_score = float(score) if isinstance(score, int | float) else None
        key = (vector or "", str(base_score))
        if key in seen:
            continue
        seen.add(key)
        records.append(
            CvssRecord(
                version=_cvss_version(vector),
                vector=vector,
                base_score=base_score,
                source=SOURCE,
            )
        )
    return tuple(records)


def _cvss_version(vector: str | None) -> CvssVersion:
    if vector is None:
        return CvssVersion.UNKNOWN
    if vector.startswith("CVSS:4.0"):
        return CvssVersion.V4_0
    if vector.startswith("CVSS:3.1"):
        return CvssVersion.V3_1
    if vector.startswith("CVSS:3.0"):
        return CvssVersion.V3_0
    if vector.startswith("CVSS:2"):
        return CvssVersion.V2_0
    return CvssVersion.UNKNOWN


def _exploitation(vulnerability: Mapping[str, Any]) -> tuple[TriState, Exploitability]:
    exploited = TriState.UNKNOWN
    exploitability = Exploitability.UNKNOWN
    for item in list_of(pick(vulnerability, "Threats")):
        node = mapping(item)
        if node is None or pick(node, "Type") != _THREAT_EXPLOIT:
            continue
        text = (text_of(pick(node, "Description")) or "").lower()
        if "exploited:yes" in text.replace(" ", ""):
            exploited = TriState.TRUE
        elif "exploited:no" in text.replace(" ", ""):
            exploited = TriState.FALSE
        if "more likely" in text:
            exploitability = Exploitability.HIGH
        elif "less likely" in text:
            exploitability = Exploitability.LOW
    return exploited, exploitability


def _references(vulnerability: Mapping[str, Any], cve: str | None) -> tuple[str, ...]:
    urls: list[str] = []
    if cve:
        urls.append(f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}")
    for item in list_of(pick(vulnerability, "Remediations")):
        node = mapping(item)
        if node is None:
            continue
        url = text_of(pick(node, "URL"))
        if url:
            urls.append(url)
    return tuple(dict.fromkeys(urls))


def _first_note(vulnerability: Mapping[str, Any], *, note_type: int) -> str | None:
    for item in list_of(pick(vulnerability, "Notes")):
        node = mapping(item)
        if node is None:
            continue
        if pick(node, "Type") == note_type:
            return text_of(pick(node, "Value")) or text_of(pick(node, "Description"))
    return None


def _cve_id(value: str | None) -> str | None:
    if value is None:
        return None
    if not _CVE.match(value):
        raise ValueError(f"invalid CVE identifier: {value}")
    return value


def _category(title: str, products: tuple[AffectedProduct, ...]) -> UpdateCategory:
    haystack = " ".join((title, *(item.product for item in products))).lower()
    if "microcode" in haystack:
        return UpdateCategory.MICROCODE
    if "firmware" in haystack:
        return UpdateCategory.FIRMWARE
    if "bios" in haystack:
        return UpdateCategory.BIOS
    if "driver" in haystack:
        return UpdateCategory.DRIVER
    if "windows" in haystack:
        return UpdateCategory.OS
    return UpdateCategory.UNKNOWN


def _architectures(name: str, cpe: str | None) -> tuple[Architecture, ...]:
    haystack = f"{name} {cpe or ''}".lower()
    found: list[Architecture] = []
    if "x64" in haystack or "64-bit" in haystack:
        found.append(Architecture.X64)
    if "x86" in haystack or "32-bit" in haystack:
        found.append(Architecture.X86)
    if "arm64" in haystack or "arm-based" in haystack:
        found.append(Architecture.ARM64)
    return tuple(found) if found else (Architecture.UNKNOWN,)


def _strip_markup(value: str) -> str:
    cleaned = _HTML_TAG.sub(" ", value)
    return re.sub(r"\s+", " ", cleaned).strip()
