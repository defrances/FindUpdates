"""Deterministic risk scoring and policy evaluation."""

from findupdates.risk.evaluate import assess, input_fingerprint
from findupdates.risk.models import (
    SCHEMA_VERSION,
    PolicyDocument,
    PolicyResult,
    RiskAssessment,
    ScoreContribution,
    SeverityBand,
)
from findupdates.risk.policy import DEFAULT_POLICY_PATH, load_policy
from findupdates.risk.serialize import assessment_to_dict, canonical_assessment_json

__all__ = [
    "DEFAULT_POLICY_PATH",
    "SCHEMA_VERSION",
    "PolicyDocument",
    "PolicyResult",
    "RiskAssessment",
    "ScoreContribution",
    "SeverityBand",
    "assess",
    "assessment_to_dict",
    "canonical_assessment_json",
    "input_fingerprint",
    "load_policy",
]
