"""Representative validation-lab framework."""

from findupdates.validation.execute import run_validation
from findupdates.validation.gates import assert_validation_gate
from findupdates.validation.models import (
    SCHEMA_VERSION,
    TestOutcome,
    ValidationPlan,
    ValidationResult,
    blocks_promotion,
)
from findupdates.validation.profiles import load_profile, load_profile_for_model
from findupdates.validation.serialize import canonical_result_json, plan_to_dict, result_to_dict
from findupdates.validation.simulator import SimulatedTarget, default_imaging_target

__all__ = [
    "SCHEMA_VERSION",
    "SimulatedTarget",
    "TestOutcome",
    "ValidationPlan",
    "ValidationResult",
    "assert_validation_gate",
    "blocks_promotion",
    "canonical_result_json",
    "default_imaging_target",
    "load_profile",
    "load_profile_for_model",
    "plan_to_dict",
    "result_to_dict",
    "run_validation",
]
