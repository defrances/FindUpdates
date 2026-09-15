"""CI device simulator. Never uses patient data or production hardware."""

from __future__ import annotations

from dataclasses import dataclass

from findupdates.validation.models import ValidationCase, VersionSnapshot


@dataclass(frozen=True, slots=True)
class SimulatedTarget:
    """Representative lab workstation used by unit tests and CI."""

    device_model: str
    baseline: VersionSnapshot
    after_update: VersionSnapshot
    fail_case_ids: frozenset[str] = frozenset()
    timeout_case_ids: frozenset[str] = frozenset()
    rollback_supported: bool = True

    def __post_init__(self) -> None:
        if not self.device_model.strip():
            raise ValueError("device_model must not be empty")


def default_imaging_target(*, fail_case_ids: frozenset[str] = frozenset()) -> SimulatedTarget:
    """Synthetic ImagingStation-X200 lab fixture."""
    baseline = VersionSnapshot("24H2-22621.2500", "5.4.2", "32.0.101.0001", "2.7.4")
    after = VersionSnapshot("24H2-22621.2600", "5.4.2", "32.0.101.0001", "2.7.4")
    return SimulatedTarget(
        device_model="ImagingStation-X200",
        baseline=baseline,
        after_update=after,
        fail_case_ids=fail_case_ids,
    )


def evaluate_case(
    case: ValidationCase,
    target: SimulatedTarget,
    *,
    signed_off: frozenset[str],
    known_issues: tuple[str, ...],
) -> tuple[str, str]:
    """Return (outcome name, detail). Installation success does not pass clinical cases."""
    if case.case_id in target.timeout_case_ids:
        return "INCONCLUSIVE", f"timed out after {case.timeout_seconds}s"
    if not case.automatable and case.case_id not in signed_off:
        return (
            "INCONCLUSIVE",
            "case cannot be automated and has no human sign-off",
        )
    if case.case_id in target.fail_case_ids:
        return "FAIL", "injected lab failure"
    if case.domain.value == "rollback" and not target.rollback_supported:
        return "FAIL", "rollback/uninstall is not available on this target"
    if case.domain.value == "known_issue" and known_issues and case.case_id not in signed_off:
        return "INCONCLUSIVE", "vendor known issues require human review"
    if case.clinical:
        return "PASS", "non-clinical smoke checks passed; not a clinical-function certification"
    return "PASS", "automated lab check passed"
