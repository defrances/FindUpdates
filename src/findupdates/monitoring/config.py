"""Version-controlled monitoring windows and pause/rollback policy."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from findupdates.monitoring.errors import MonitoringError
from findupdates.monitoring.models import HealthDomain, HealthState

_CONFIG = Path(__file__).resolve().parents[3] / "configs" / "monitoring" / "v1.json"


def load_monitoring_config(path: Path | None = None) -> dict[str, Any]:
    """Load draft monitoring thresholds. Invalid documents fail closed."""
    payload = json.loads((path or _CONFIG).read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("version") != "1.0":
        raise MonitoringError("unsupported monitoring config version")
    return {str(key): value for key, value in payload.items()}


def observation_window_minutes(
    config: dict[str, Any],
    *,
    update_kind: str,
    clinical_criticality: str,
) -> int:
    """Longer windows for firmware and clinically critical devices."""
    windows = config["windows_minutes"]
    key = f"{update_kind}:{clinical_criticality}"
    if key in windows:
        return int(windows[key])
    fallback = f"{update_kind}:medium"
    if fallback in windows:
        return int(windows[fallback])
    return int(windows["default"])


def critical_domains(config: dict[str, Any]) -> frozenset[HealthDomain]:
    return frozenset(HealthDomain(item) for item in config["critical_domains"])


def pause_states(config: dict[str, Any]) -> frozenset[HealthState]:
    return frozenset(HealthState(item) for item in config["pause_on"])


def rollback_permitted_domains(config: dict[str, Any]) -> frozenset[HealthDomain]:
    return frozenset(HealthDomain(item) for item in config["rollback_permitted_domains"])


def rollback_enabled_for(config: dict[str, Any], update_kind: str) -> bool:
    return update_kind in set(config["rollback_enabled_kinds"])
