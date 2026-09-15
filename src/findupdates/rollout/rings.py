"""Deterministic ring membership. Critical devices skip early rings."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from math import ceil

from findupdates.deployment.hashing import target_set_hash
from findupdates.rollout.errors import RolloutDenied
from findupdates.rollout.models import STAGE_ORDER, RolloutDevice

_EARLY_RINGS = frozenset({"canary", "ring-1"})


def membership_hash(device_ids: Sequence[str]) -> str:
    """Hash a ring snapshot. Empty rings hash the empty payload, not an invented device."""
    if not device_ids:
        return hashlib.sha256(b"").hexdigest()
    return target_set_hash(device_ids)


def plan_membership_hash(stages: Mapping[str, Sequence[str]]) -> str:
    """Hash the full ordered membership map."""
    payload = {name: list(stages.get(name, ())) for name in STAGE_ORDER}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def assign_rings(
    devices: Sequence[RolloutDevice],
    *,
    canary_percent: int,
    ring_1_percent: int,
    explicit: Mapping[str, Sequence[str]] | None = None,
) -> dict[str, tuple[str, ...]]:
    """Assign each device to one first-deploy stage. Critical devices skip canary/ring-1."""
    if not devices:
        raise ValueError("rollout requires at least one device")
    by_id = {item.device_id: item for item in devices}
    if explicit:
        return _explicit(by_id, explicit)
    lab = tuple(sorted(item.device_id for item in devices if item.is_lab))
    fleet = [item for item in devices if not item.is_lab]
    if not lab:
        raise RolloutDenied("rollout requires at least one lab device")
    critical = sorted(item.device_id for item in fleet if item.is_clinical_critical)
    standard = sorted(item.device_id for item in fleet if not item.is_clinical_critical)
    canary_n = _count(len(standard), canary_percent)
    ring1_n = _count(len(standard), ring_1_percent)
    canary = tuple(standard[:canary_n])
    ring1 = tuple(standard[canary_n : canary_n + ring1_n])
    leftover = standard[canary_n + ring1_n :]
    ring2 = tuple(leftover)
    production = tuple(critical)
    return {
        "lab": lab,
        "canary": canary,
        "ring-1": ring1,
        "ring-2": ring2,
        "production": production,
    }


def _count(total: int, percent: int) -> int:
    if total == 0 or percent <= 0:
        return 0
    return min(total, max(1, ceil(total * percent / 100)))


def _explicit(
    by_id: Mapping[str, RolloutDevice],
    explicit: Mapping[str, Sequence[str]],
) -> dict[str, tuple[str, ...]]:
    assigned: set[str] = set()
    result: dict[str, tuple[str, ...]] = {}
    for name in STAGE_ORDER:
        ids = tuple(dict.fromkeys(explicit.get(name, ())))
        for device_id in ids:
            device = by_id.get(device_id)
            if device is None:
                raise RolloutDenied(f"unknown device {device_id} in stage {name}")
            if device_id in assigned:
                raise RolloutDenied(f"device {device_id} is assigned to multiple rings")
            if name in _EARLY_RINGS and device.is_clinical_critical:
                raise RolloutDenied(f"clinically critical device {device_id} cannot join {name}")
            assigned.add(device_id)
        result[name] = ids
    missing = set(by_id) - assigned
    if missing:
        raise RolloutDenied(f"devices missing from ring snapshot: {', '.join(sorted(missing))}")
    if not result["lab"]:
        raise RolloutDenied("rollout requires at least one lab device")
    return result
