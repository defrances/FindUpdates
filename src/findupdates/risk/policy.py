"""Load and validate versioned policy documents."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from findupdates.collectors.jsonutil import sha256_bytes
from findupdates.risk.models import PolicyDocument, PolicyResult, SeverityBand

DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[3] / "configs" / "policies" / "v1.json"


def load_policy(path: Path | None = None) -> PolicyDocument:
    """Load a policy JSON document. Invalid policy fails closed."""
    policy_path = path or DEFAULT_POLICY_PATH
    raw = policy_path.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"policy file is not valid JSON: {policy_path}") from exc
    if not isinstance(payload, dict):
        raise ValueError("policy document must be a JSON object")
    return parse_policy(payload, source_sha256=sha256_bytes(raw))


def parse_policy(payload: dict[str, Any], *, source_sha256: str) -> PolicyDocument:
    """Validate policy structure, bands and gate enumerations."""
    version = _text(payload.get("version"))
    status = _text(payload.get("status"))
    score_cap = payload.get("score_cap")
    if not isinstance(score_cap, int) or score_cap != 100:
        raise ValueError("score_cap must be integer 100")
    weights = _float_map(payload.get("weights"), "weights")
    modifiers = _float_map(payload.get("modifiers"), "modifiers")
    bands = _bands(payload.get("bands"))
    band_policy = _band_policy(payload.get("band_policy"))
    if set(bands) != set(band_policy):
        raise ValueError("band_policy must cover every severity band")
    hard_gates = _hard_gates(payload.get("hard_gates"))
    return PolicyDocument(
        version=version,
        status=status,
        score_cap=score_cap,
        weights=weights,
        modifiers=modifiers,
        bands=bands,
        band_policy=band_policy,
        hard_gates=hard_gates,
        source_sha256=source_sha256,
    )


def _bands(value: object) -> dict[SeverityBand, tuple[int, int]]:
    if not isinstance(value, dict) or not value:
        raise ValueError("bands must be a non-empty object")
    parsed: dict[SeverityBand, tuple[int, int]] = {}
    for name, span in value.items():
        band = SeverityBand(str(name))
        if not isinstance(span, list) or len(span) != 2:
            raise ValueError(f"band {band.value} must be [low, high]")
        low, high = span
        if not isinstance(low, int) or not isinstance(high, int) or low > high:
            raise ValueError(f"band {band.value} bounds must be integers with low <= high")
        parsed[band] = (low, high)
    ordered = [parsed[band] for band in SeverityBand if band in parsed]
    if set(parsed) != set(SeverityBand):
        raise ValueError("all severity bands must be defined")
    if ordered[0][0] != 0 or ordered[-1][1] != 100:
        raise ValueError("bands must cover 0 through 100")
    previous = -1
    for low, high in ordered:
        if low != previous + 1:
            raise ValueError("severity bands must be contiguous")
        previous = high
    return parsed


def _band_policy(value: object) -> dict[SeverityBand, PolicyResult]:
    if not isinstance(value, dict):
        raise ValueError("band_policy must be an object")
    return {SeverityBand(str(name)): PolicyResult(str(result)) for name, result in value.items()}


def _hard_gates(value: object) -> dict[str, PolicyResult]:
    if not isinstance(value, dict) or not value:
        raise ValueError("hard_gates must be a non-empty object")
    gates: dict[str, PolicyResult] = {}
    for name, result in value.items():
        key = str(name).strip()
        if not key:
            raise ValueError("hard gate name must not be empty")
        gates[key] = PolicyResult(str(result))
    return gates


def _float_map(value: object, field: str) -> dict[str, float]:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    mapped: dict[str, float] = {}
    for key, raw in value.items():
        name = str(key).strip()
        if not name:
            raise ValueError(f"{field} keys must not be empty")
        if not isinstance(raw, int | float) or isinstance(raw, bool) or raw < 0:
            raise ValueError(f"{field}.{name} must be a non-negative number")
        mapped[name] = float(raw)
    return mapped


def _text(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("policy text fields must be non-empty strings")
    return value.strip()
