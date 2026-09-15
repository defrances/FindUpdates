"""Apply NVD/KEV facts onto an UpdateAdvisory without replacing vendor applicability."""

from __future__ import annotations

from dataclasses import replace

from findupdates.enrichment.models import CveEnrichment
from findupdates.normalization.models import (
    Conflict,
    CvssRecord,
    FieldProvenance,
    TriState,
    UpdateAdvisory,
    completeness_for,
    incomplete_fields_for,
)


def apply_enrichment(
    advisory: UpdateAdvisory, records: tuple[CveEnrichment, ...]
) -> UpdateAdvisory:
    """Return a copy of the advisory with NVD CVSS and KEV exploitation signals applied.

    Vendor affected_products are left unchanged. KEV listing can raise known_exploited to
    true; absence from KEV never forces false.
    """
    nvd_cvss = tuple(item for record in records for item in record.nvd_cvss)
    merged_cvss = _unique_cvss((*advisory.cvss, *nvd_cvss))
    vendor_state = advisory.known_exploited
    kev_true = any(record.kev_listed is TriState.TRUE for record in records)
    known_exploited = _effective_known_exploited(vendor_state, kev_true)
    conflicts = list(advisory.conflicts)
    if kev_true and vendor_state is TriState.FALSE:
        conflicts.append(
            Conflict(
                field_path="known_exploited",
                reason="vendor asserted false; CISA KEV lists at least one CVE",
            )
        )
    provenance = list(advisory.field_provenance)
    if nvd_cvss:
        provenance.append(FieldProvenance("cvss", "nvd"))
    if records:
        provenance.append(FieldProvenance("known_exploited", "cisa-kev"))
    updated = replace(
        advisory,
        cvss=merged_cvss,
        known_exploited=known_exploited,
        conflicts=_unique_conflicts(tuple(conflicts)),
        field_provenance=_unique_provenance(tuple(provenance)),
    )
    missing = incomplete_fields_for(updated)
    return replace(
        updated,
        incomplete_fields=missing,
        completeness=completeness_for(missing),
    )


def _effective_known_exploited(vendor_state: TriState, kev_true: bool) -> TriState:
    if kev_true or vendor_state is TriState.TRUE:
        return TriState.TRUE
    return vendor_state


def _unique_cvss(values: tuple[CvssRecord, ...]) -> tuple[CvssRecord, ...]:
    unique: dict[tuple[str, str | None, str], CvssRecord] = {}
    for record in values:
        unique[(record.version.value, record.vector, record.source)] = record

    def _sort_key(item: tuple[str, str | None, str]) -> str:
        version, vector, source = item
        return version + (vector or "") + source

    return tuple(unique[key] for key in sorted(unique, key=_sort_key))


def _unique_conflicts(values: tuple[Conflict, ...]) -> tuple[Conflict, ...]:
    unique: dict[tuple[str, str], Conflict] = {}
    for item in values:
        unique[(item.field_path, item.reason)] = item
    return tuple(unique[key] for key in sorted(unique))


def _unique_provenance(values: tuple[FieldProvenance, ...]) -> tuple[FieldProvenance, ...]:
    unique: dict[tuple[str, str], FieldProvenance] = {}
    for item in values:
        unique[(item.field_path, item.source)] = item
    return tuple(unique[key] for key in sorted(unique))
