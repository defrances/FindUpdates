"""Promotion gate: required validation evidence cannot be overridden by workflow inputs."""

from __future__ import annotations

from findupdates.changerecords.models import PromotionDenied
from findupdates.validation.models import TestOutcome, ValidationResult, blocks_promotion


def assert_validation_gate(result: ValidationResult, target_environment: str) -> None:
    """Fail closed when required tests are FAIL, BLOCKED or INCONCLUSIVE."""
    if target_environment == "lab":
        return
    if target_environment not in {"canary", "production"}:
        raise PromotionDenied(f"unknown environment {target_environment}")
    if blocks_promotion(result):
        raise PromotionDenied(
            f"validation overall={result.overall.value} blocks {target_environment} promotion"
        )
    if result.overall is not TestOutcome.PASS:
        raise PromotionDenied("validation did not pass")
