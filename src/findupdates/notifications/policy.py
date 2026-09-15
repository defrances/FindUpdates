"""Load severity-to-channel routing policy. Invalid policy fails closed."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from findupdates.notifications.models import RoutingPolicy

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[3] / "configs" / "notifications" / "v1.json"

_KNOWN_CHANNELS = frozenset({"github", "webhook", "email", "teams", "slack", "siem"})
_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL", "EMERGENCY"})


def load_routing_policy(path: Path | None = None) -> RoutingPolicy:
    """Load notification routing JSON."""
    policy_path = path or DEFAULT_POLICY_PATH
    raw = policy_path.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"notification policy is not valid JSON: {policy_path}") from exc
    if not isinstance(payload, dict):
        raise ValueError("notification policy must be a JSON object")
    return parse_routing_policy(payload)


def parse_routing_policy(payload: dict[str, Any]) -> RoutingPolicy:
    """Validate routing structure and enumerations."""
    version = _text(payload.get("version"))
    channels_raw = payload.get("channels")
    if not isinstance(channels_raw, dict) or not channels_raw:
        raise ValueError("channels must be a non-empty object")
    channels: dict[str, tuple[str, ...]] = {}
    for severity, names in channels_raw.items():
        band = str(severity)
        if band not in _SEVERITIES:
            raise ValueError(f"unknown severity in channels: {band}")
        if not isinstance(names, list) or not names:
            raise ValueError(f"channels.{band} must be a non-empty array")
        parsed = tuple(str(item) for item in names)
        unknown = [item for item in parsed if item not in _KNOWN_CHANNELS]
        if unknown:
            raise ValueError(f"unsupported channel names: {unknown}")
        channels[band] = parsed
    ack = frozenset(str(item) for item in _str_list(payload.get("acknowledge_required")))
    if not ack <= _SEVERITIES:
        raise ValueError("acknowledge_required must use known severity bands")
    escalate_raw = payload.get("escalate_after_minutes")
    if not isinstance(escalate_raw, dict):
        raise ValueError("escalate_after_minutes must be an object")
    escalate = {str(key): _positive_int(value) for key, value in escalate_raw.items()}
    low = frozenset(str(item) for item in _str_list(payload.get("low_priority_severities")))
    window = _positive_int(payload.get("low_priority_batch_window_minutes"))
    rate = _positive_int(payload.get("low_priority_rate_limit"))
    retries = _positive_int(payload.get("retry_attempts"))
    return RoutingPolicy(
        version=version,
        channels=channels,
        acknowledge_required=ack,
        escalate_after_minutes=escalate,
        low_priority_severities=low,
        low_priority_batch_window_minutes=window,
        low_priority_rate_limit=rate,
        retry_attempts=retries,
    )


def _str_list(value: object) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("expected an array of strings")
    return [str(item) for item in value]


def _positive_int(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError("expected a positive integer")
    return value


def _text(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("policy text fields must be non-empty strings")
    return value.strip()
