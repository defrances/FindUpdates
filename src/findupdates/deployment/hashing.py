"""Canonical hashes for approved target sets."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from findupdates.deployment.models import DeploymentTarget


def target_set_hash(device_ids: Sequence[str]) -> str:
    """Return a SHA-256 digest of the sorted, unique device identifiers."""
    cleaned = [item.strip() for item in device_ids]
    if not cleaned or any(not item for item in cleaned):
        raise ValueError("target set requires non-empty device ids")
    if len(set(cleaned)) != len(cleaned):
        raise ValueError("target set must not contain duplicate device ids")
    canonical = "\n".join(sorted(cleaned))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def hash_targets(targets: Sequence[DeploymentTarget]) -> str:
    """Hash the device ids of a target tuple."""
    return target_set_hash([item.device_id for item in targets])
