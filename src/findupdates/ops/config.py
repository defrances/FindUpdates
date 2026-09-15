"""Version-controlled operational policy: kill switch, freshness and scanners."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from findupdates.ops.errors import OpsError

_CONFIG = Path(__file__).resolve().parents[3] / "configs" / "operations" / "v1.json"


def load_operations_config(path: Path | None = None) -> dict[str, Any]:
    payload = json.loads((path or _CONFIG).read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("version") != "1.0":
        raise OpsError("unsupported operations config version")
    return {str(key): value for key, value in payload.items()}


def deployments_enabled(
    config: dict[str, Any],
    *,
    environ: Mapping[str, str] | None = None,
) -> tuple[bool, str]:
    """Env FINDUPDATES_DEPLOYMENTS_ENABLED overrides file policy for emergencies."""
    env: Mapping[str, str] = os.environ if environ is None else environ
    raw = env.get("FINDUPDATES_DEPLOYMENTS_ENABLED")
    if raw is not None and raw.strip():
        enabled = raw.strip().lower() in {"1", "true", "yes", "on"}
        reason = "environment kill switch" if not enabled else "environment override"
        return enabled, reason
    enabled = bool(config.get("deployments_enabled", False))
    reason = str(config.get("disabled_reason") or "operations policy")
    return enabled, reason


def freshness_hours(config: dict[str, Any], source: str) -> int:
    windows = config["freshness_hours"]
    if source not in windows:
        raise OpsError(f"no freshness target for source {source}")
    return int(windows[source])


def scanner_block_severities(config: dict[str, Any]) -> frozenset[str]:
    return frozenset(str(item).lower() for item in config["scanner_block_severity"])


def dead_letter_max_attempts(config: dict[str, Any]) -> int:
    return int(config["dead_letter_max_attempts"])
