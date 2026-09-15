"""Deterministic update-to-device applicability evaluation."""

from findupdates.applicability.evaluate import evaluate, evaluate_many, input_fingerprint
from findupdates.applicability.models import (
    SCHEMA_VERSION,
    ApplicabilityEvidence,
    ApplicabilityResult,
    ApplicabilityVerdict,
    ReasonCode,
)
from findupdates.applicability.serialize import canonical_result_json, result_to_dict

__all__ = [
    "SCHEMA_VERSION",
    "ApplicabilityEvidence",
    "ApplicabilityResult",
    "ApplicabilityVerdict",
    "ReasonCode",
    "canonical_result_json",
    "evaluate",
    "evaluate_many",
    "input_fingerprint",
    "result_to_dict",
]
