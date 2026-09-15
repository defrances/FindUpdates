"""Deterministic advisory-to-device applicability evaluation."""

from __future__ import annotations

from datetime import datetime

from findupdates.applicability.intel import match_intel_product
from findupdates.applicability.models import (
    ApplicabilityEvidence,
    ApplicabilityResult,
    ApplicabilityVerdict,
    IdentityStrength,
    MatchObservation,
    ReasonCode,
    VersionRelation,
    blocks_automatic_deployment,
)
from findupdates.applicability.sbom import match_sbom_product
from findupdates.applicability.windows import match_windows_product
from findupdates.ids import stable_id
from findupdates.inventory.models import DeviceInventory, FreshnessState, VerificationState
from findupdates.normalization.models import Confidence, ProductStatus, UpdateAdvisory

_STRONG = frozenset({IdentityStrength.PRODUCT_ID, IdentityStrength.CPE, IdentityStrength.PURL})


def evaluate(
    advisory: UpdateAdvisory,
    device: DeviceInventory,
    *,
    now: datetime,
    previous_fingerprint: str | None = None,
) -> ApplicabilityResult:
    """Evaluate one advisory against one device without calling an LLM."""
    fingerprint = input_fingerprint(advisory, device)
    freshness = device.evaluated_freshness()
    evidence: list[ApplicabilityEvidence] = []
    missing: list[str] = []

    if freshness is FreshnessState.STALE:
        evidence.append(_note(ReasonCode.STALE_INVENTORY, "inventory exceeds freshness max age"))
    elif freshness is FreshnessState.UNKNOWN:
        evidence.append(
            _note(ReasonCode.FRESHNESS_UNKNOWN, "inventory freshness could not be evaluated")
        )
    if device.source_confidence in {VerificationState.UNVERIFIED, VerificationState.UNKNOWN}:
        evidence.append(
            _note(ReasonCode.UNVERIFIED_INVENTORY, "inventory source confidence is not verified")
        )

    if not advisory.affected_products:
        evidence.append(
            _note(
                ReasonCode.EMPTY_AFFECTED_PRODUCTS,
                "advisory lists no affected products; cannot prove not_affected",
                source_fields=("affected_products",),
            )
        )
        return _result(
            advisory,
            device,
            fingerprint,
            now,
            previous_fingerprint,
            ApplicabilityVerdict.UNKNOWN,
            Confidence.UNKNOWN,
            evidence,
            missing=("affected_products",),
            inventory_fresh=freshness is FreshnessState.FRESH,
        )

    observations = _observations(advisory, device)
    verdict, confidence, extra, missing_fields = _combine(observations, device, freshness)
    evidence.extend(extra)
    missing.extend(missing_fields)
    if not evidence:
        evidence.append(
            _note(ReasonCode.NO_DETERMINISTIC_MATCH, "no vendor or SBOM identity matched")
        )
    return _result(
        advisory,
        device,
        fingerprint,
        now,
        previous_fingerprint,
        verdict,
        confidence,
        evidence,
        missing=tuple(dict.fromkeys(missing)),
        inventory_fresh=freshness is FreshnessState.FRESH,
    )


def evaluate_many(
    advisories: tuple[UpdateAdvisory, ...] | list[UpdateAdvisory],
    devices: tuple[DeviceInventory, ...] | list[DeviceInventory],
    *,
    now: datetime,
    previous_fingerprints: dict[tuple[str, str], str] | None = None,
) -> tuple[ApplicabilityResult, ...]:
    """Evaluate every pair in deterministic advisory_id, device_id order."""
    previous = previous_fingerprints or {}
    results: list[ApplicabilityResult] = []
    for advisory in sorted(advisories, key=lambda item: item.advisory_id):
        for device in sorted(devices, key=lambda item: item.device_id):
            results.append(
                evaluate(
                    advisory,
                    device,
                    now=now,
                    previous_fingerprint=previous.get((advisory.advisory_id, device.device_id)),
                )
            )
    return tuple(results)


def input_fingerprint(advisory: UpdateAdvisory, device: DeviceInventory) -> str:
    """Hash the inputs that must trigger reassessment when they change."""
    revised = advisory.revised_at or advisory.published_at
    return stable_id(
        "applicability",
        advisory.advisory_id,
        revised.isoformat(),
        advisory.provenance.raw_sha256,
        device.device_id,
        device.inventory_timestamp.isoformat(),
        device.freshness_state.value,
        str(device.freshness_max_age_hours),
    )


def _observations(
    advisory: UpdateAdvisory, device: DeviceInventory
) -> tuple[MatchObservation, ...]:
    found: list[MatchObservation] = []
    for product in advisory.affected_products:
        candidates = [
            match_windows_product(product, device, advisory),
            match_intel_product(product, device, advisory),
            match_sbom_product(product, device, advisory),
        ]
        present = [item for item in candidates if item is not None]
        if present:
            found.append(max(present, key=_observation_rank))
    return tuple(found)


def _combine(
    observations: tuple[MatchObservation, ...],
    device: DeviceInventory,
    freshness: FreshnessState,
) -> tuple[ApplicabilityVerdict, Confidence, list[ApplicabilityEvidence], list[str]]:
    evidence = [item for observation in observations for item in _evidence_from(observation)]
    missing: list[str] = []
    strong_affected: list[MatchObservation] = []
    strong_not: list[MatchObservation] = []
    strong_missing: list[MatchObservation] = []
    family_affected: list[MatchObservation] = []
    family_ambiguous: list[MatchObservation] = []
    for item in observations:
        if item.version_relation is VersionRelation.MISSING:
            missing.append("version")
            if item.identity in _STRONG:
                strong_missing.append(item)
            else:
                family_ambiguous.append(item)
            continue
        if _is_affected(item):
            if item.identity in _STRONG:
                strong_affected.append(item)
            else:
                family_affected.append(item)
        elif _is_not_affected(item):
            if item.identity in _STRONG:
                strong_not.append(item)
            else:
                family_ambiguous.append(item)
        elif item.identity in _STRONG:
            strong_missing.append(item)
            missing.append("version_or_status")
        else:
            family_ambiguous.append(item)

    conservative = freshness is not FreshnessState.FRESH or not _allows_negative(device)

    if strong_affected:
        confidence = Confidence.HIGH if freshness is FreshnessState.FRESH else Confidence.MEDIUM
        return ApplicabilityVerdict.AFFECTED, confidence, evidence, missing
    if family_affected:
        return ApplicabilityVerdict.AFFECTED, Confidence.MEDIUM, evidence, missing
    if strong_missing:
        evidence.append(
            _note(ReasonCode.MISSING_VERSION, "matched product identity but version is incomplete")
        )
        return ApplicabilityVerdict.POSSIBLY_AFFECTED, Confidence.LOW, evidence, missing
    if strong_not:
        if conservative:
            return (
                ApplicabilityVerdict.POSSIBLY_AFFECTED,
                Confidence.LOW,
                evidence,
                missing,
            )
        return ApplicabilityVerdict.NOT_AFFECTED, Confidence.HIGH, evidence, missing
    if family_ambiguous:
        evidence.append(
            _note(
                ReasonCode.NAME_AMBIGUOUS,
                "free-text product family match is not sufficient for not_affected",
            )
        )
        return ApplicabilityVerdict.POSSIBLY_AFFECTED, Confidence.LOW, evidence, missing
    evidence.append(
        _note(
            ReasonCode.NO_DETERMINISTIC_MATCH,
            "device identifiers did not match advisory product rows",
        )
    )
    return ApplicabilityVerdict.UNKNOWN, Confidence.UNKNOWN, evidence, missing


def _is_affected(item: MatchObservation) -> bool:
    if item.architecture_match is False:
        return False
    status = ProductStatus(item.product_status_value)
    if status is ProductStatus.NOT_AFFECTED:
        return False
    if item.version_relation in {VersionRelation.IN_RANGE, VersionRelation.BELOW_FIXED}:
        return True
    if item.version_relation is VersionRelation.NOT_APPLICABLE and status is ProductStatus.AFFECTED:
        return item.identity in _STRONG
    return False


def _is_not_affected(item: MatchObservation) -> bool:
    status = ProductStatus(item.product_status_value)
    if item.architecture_match is False and item.identity in _STRONG:
        return True
    if status is ProductStatus.NOT_AFFECTED and item.identity in _STRONG:
        return True
    if (
        item.version_relation
        in {
            VersionRelation.OUT_OF_RANGE,
            VersionRelation.AT_OR_ABOVE_FIXED,
        }
        and item.identity in _STRONG
    ):
        return True
    return (
        status is ProductStatus.FIXED and item.version_relation is VersionRelation.AT_OR_ABOVE_FIXED
    )


def _allows_negative(device: DeviceInventory) -> bool:
    if device.source_confidence in {VerificationState.UNVERIFIED, VerificationState.UNKNOWN}:
        return False
    return device.os.verification_state not in {
        VerificationState.UNVERIFIED,
        VerificationState.UNKNOWN,
    }


def _result(
    advisory: UpdateAdvisory,
    device: DeviceInventory,
    fingerprint: str,
    now: datetime,
    previous_fingerprint: str | None,
    verdict: ApplicabilityVerdict,
    confidence: Confidence,
    evidence: list[ApplicabilityEvidence],
    *,
    missing: tuple[str, ...],
    inventory_fresh: bool,
) -> ApplicabilityResult:
    unique = tuple(_unique_evidence(evidence))
    source_fields = tuple(dict.fromkeys(field for item in unique for field in item.source_fields))
    inventory_fields = tuple(
        dict.fromkeys(field for item in unique for field in item.inventory_fields)
    )
    return ApplicabilityResult(
        result_id=stable_id("applicability-result", fingerprint),
        advisory_id=advisory.advisory_id,
        device_id=device.device_id,
        verdict=verdict,
        confidence=confidence,
        blocks_automatic_deployment=blocks_automatic_deployment(
            verdict, confidence, inventory_fresh=inventory_fresh
        ),
        evidence=unique,
        source_fields=source_fields,
        inventory_fields=inventory_fields,
        missing_data=missing,
        input_fingerprint=fingerprint,
        evaluated_at=now,
        needs_reassessment=previous_fingerprint is not None and previous_fingerprint != fingerprint,
        previous_fingerprint=previous_fingerprint,
    )


def _evidence_from(item: MatchObservation) -> list[ApplicabilityEvidence]:
    codes = item.reason_codes or (ReasonCode.NO_DETERMINISTIC_MATCH,)
    return [
        ApplicabilityEvidence(
            reason_code=code,
            detail=item.detail,
            source_fields=item.source_fields,
            inventory_fields=item.inventory_fields,
        )
        for code in codes
    ]


def _note(
    code: ReasonCode,
    detail: str,
    *,
    source_fields: tuple[str, ...] = (),
    inventory_fields: tuple[str, ...] = (),
) -> ApplicabilityEvidence:
    return ApplicabilityEvidence(
        reason_code=code,
        detail=detail,
        source_fields=source_fields,
        inventory_fields=inventory_fields,
    )


def _unique_evidence(items: list[ApplicabilityEvidence]) -> list[ApplicabilityEvidence]:
    unique: dict[tuple[str, str], ApplicabilityEvidence] = {}
    for item in items:
        unique[(item.reason_code.value, item.detail)] = item
    return [unique[key] for key in sorted(unique)]


def _observation_rank(item: MatchObservation) -> tuple[int, int]:
    identity_rank = {
        IdentityStrength.PRODUCT_ID: 4,
        IdentityStrength.CPE: 3,
        IdentityStrength.PURL: 3,
        IdentityStrength.FAMILY: 1,
        IdentityStrength.NONE: 0,
    }[item.identity]
    return identity_rank, len(item.reason_codes)
