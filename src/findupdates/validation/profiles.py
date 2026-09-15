"""Version-controlled validation profiles associated with a device model."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from findupdates.validation.models import TestDomain, ValidationCase, ValidationPlan

DEFAULT_PROFILE_DIR = Path(__file__).resolve().parents[3] / "configs" / "validation" / "profiles"


def load_profile(path: Path) -> ValidationPlan:
    """Load one device-model profile. Invalid JSON fails closed."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("validation profile must be a JSON object")
    return parse_plan(raw)


def load_profile_for_model(device_model: str, *, directory: Path | None = None) -> ValidationPlan:
    """Select the profile whose device_model matches. Ambiguity fails closed."""
    root = directory or DEFAULT_PROFILE_DIR
    plans = [load_profile(path) for path in sorted(root.glob("*.json"))]
    matches = [item for item in plans if item.device_model == device_model]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one profile for model {device_model}")
    return matches[0]


def parse_plan(payload: dict[str, Any]) -> ValidationPlan:
    """Parse a ValidationPlan mapping."""
    cases_raw = payload.get("cases")
    if not isinstance(cases_raw, list) or not cases_raw:
        raise ValueError("cases must be a non-empty array")
    cases = tuple(_case(item) for item in cases_raw)
    return ValidationPlan(
        profile_id=_text(payload.get("profile_id")),
        profile_version=_text(payload.get("profile_version")),
        device_model=_text(payload.get("device_model")),
        baseline_id=_text(payload.get("baseline_id")),
        cases=cases,
        schema_version=_text(payload.get("schema_version")),
    )


def _case(value: object) -> ValidationCase:
    if not isinstance(value, dict):
        raise ValueError("case must be an object")
    timeout = value.get("timeout_seconds")
    if not isinstance(timeout, int) or isinstance(timeout, bool):
        raise ValueError("timeout_seconds must be an integer")
    return ValidationCase(
        case_id=_text(value.get("case_id")),
        domain=TestDomain(str(value.get("domain"))),
        title=_text(value.get("title")),
        mandatory=bool(value.get("mandatory")),
        automatable=bool(value.get("automatable")),
        clinical=bool(value.get("clinical")),
        timeout_seconds=timeout,
    )


def _text(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("profile text fields must be non-empty strings")
    return value.strip()
