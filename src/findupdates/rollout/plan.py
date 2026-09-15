"""Build an immutable rollout plan from devices, package identity and policy."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from findupdates.ids import stable_id
from findupdates.rollout.errors import RolloutDenied
from findupdates.rollout.models import (
    STAGE_ORDER,
    EmergencyOverride,
    RolloutDevice,
    RolloutPlan,
    StageSpec,
    stage_environment,
)
from findupdates.rollout.rings import assign_rings, membership_hash, plan_membership_hash

_CONFIG = Path(__file__).resolve().parents[3] / "configs" / "rollout" / "v1.json"


def load_rollout_config(path: Path | None = None) -> dict[str, Any]:
    """Load versioned ring percentages and stage thresholds."""
    payload = json.loads((path or _CONFIG).read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("version") != "1.0":
        raise RolloutDenied("unsupported rollout config version")
    loaded: dict[str, Any] = {str(key): value for key, value in payload.items()}
    return loaded


def build_plan(
    devices: Sequence[RolloutDevice],
    *,
    package_id: str,
    package_sha256: str,
    change_idempotency_key: str,
    policy_result: str,
    now: datetime,
    config: Mapping[str, Any] | None = None,
    explicit: Mapping[str, Sequence[str]] | None = None,
    emergency: EmergencyOverride | None = None,
    observation_overrides: Mapping[str, int] | None = None,
) -> RolloutPlan:
    """Snapshot ring membership. A later membership change needs a new plan."""
    document = dict(config or load_rollout_config())
    selection = document["selection"]
    assigned = assign_rings(
        devices,
        canary_percent=int(selection["canary_percent"]),
        ring_1_percent=int(selection["ring_1_percent"]),
        explicit=explicit,
    )
    stages = []
    for name in STAGE_ORDER:
        defaults = document["stages"][name]
        window = (
            observation_overrides[name]
            if observation_overrides is not None and name in observation_overrides
            else int(defaults["observation_window_minutes"])
        )
        members = assigned[name]
        stages.append(
            StageSpec(
                name=name,
                environment=stage_environment(name),
                member_device_ids=members,
                membership_hash=membership_hash(members),
                observation_window_minutes=window,
                max_failure_rate=float(defaults["max_failure_rate"]),
                max_crash_count=int(defaults["max_crash_count"]),
                max_connectivity_loss=int(defaults["max_connectivity_loss"]),
                max_validation_regressions=int(defaults["max_validation_regressions"]),
                requires_approval=bool(defaults["requires_approval"]),
                maintenance_required=bool(defaults["maintenance_required"]),
            )
        )
    frozen = tuple(stages)
    return RolloutPlan(
        plan_id=stable_id("rollout-plan", change_idempotency_key, package_sha256),
        change_idempotency_key=change_idempotency_key,
        policy_result=policy_result,
        package_id=package_id,
        package_sha256=package_sha256,
        stages=frozen,
        membership_hash=plan_membership_hash(
            {item.name: item.member_device_ids for item in frozen}
        ),
        emergency=emergency or EmergencyOverride(False, "", ""),
        created_at=now,
    )
