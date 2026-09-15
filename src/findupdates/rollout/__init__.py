"""Staged canary/ring rollout with deterministic promotion gates."""

from findupdates.rollout.controller import RolloutController
from findupdates.rollout.errors import ConcurrentRollout, RolloutDenied, ScopeChanged
from findupdates.rollout.models import (
    SCHEMA_VERSION,
    STAGE_ORDER,
    EmergencyOverride,
    HealthSignals,
    MaintenanceWindow,
    PromotionEvent,
    RolloutDevice,
    RolloutPlan,
    RolloutState,
    RolloutStatus,
    StageStatus,
)
from findupdates.rollout.plan import build_plan, load_rollout_config
from findupdates.rollout.serialize import (
    dict_to_plan,
    dict_to_state,
    plan_to_dict,
    state_to_dict,
)
from findupdates.rollout.simulate import ALWAYS_OPEN, NIGHTLY, synthetic_fleet
from findupdates.rollout.windows import in_maintenance_window

__all__ = [
    "ALWAYS_OPEN",
    "NIGHTLY",
    "SCHEMA_VERSION",
    "STAGE_ORDER",
    "ConcurrentRollout",
    "EmergencyOverride",
    "HealthSignals",
    "MaintenanceWindow",
    "PromotionEvent",
    "RolloutController",
    "RolloutDenied",
    "RolloutDevice",
    "RolloutPlan",
    "RolloutState",
    "RolloutStatus",
    "ScopeChanged",
    "StageStatus",
    "build_plan",
    "dict_to_plan",
    "dict_to_state",
    "in_maintenance_window",
    "load_rollout_config",
    "plan_to_dict",
    "state_to_dict",
    "synthetic_fleet",
]
