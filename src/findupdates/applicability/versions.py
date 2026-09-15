"""Deterministic version and range comparison for applicability matching."""

from __future__ import annotations

import re
from dataclasses import dataclass

_NUMERIC = re.compile(r"\d+")
_RANGE_TOKEN = re.compile(r"(>=|<=|>|<|==|=)?\s*[vV]?(\d+(?:\.\d+)*)")
_HYPHEN_RANGE = re.compile(r"^\s*([vV]?\d+(?:\.\d+)*)\s*-\s*([vV]?\d+(?:\.\d+)*)\s*$")
_WINDOWS_PREFIXES = {(10, 0), (6, 1), (6, 2), (6, 3)}


@dataclass(frozen=True, slots=True)
class VersionBound:
    op: str
    version: str


def parse_numeric_version(value: str) -> tuple[int, ...]:
    """Extract dotted numeric segments. Non-numeric labels are ignored."""
    parts = tuple(int(part) for part in _NUMERIC.findall(value))
    if not parts:
        raise ValueError(f"no numeric version in {value!r}")
    return parts


def compare_versions(left: str, right: str) -> int:
    """Return -1, 0, or 1 after aligning Windows-style prefixes when needed."""
    return _cmp_tuples(
        *align_version_tuples(parse_numeric_version(left), parse_numeric_version(right))
    )


def compare_windows_versions(left: str, right: str) -> int:
    """Compare Windows NT versions using build number, then UBR when present."""
    left_build = windows_build_number(left)
    right_build = windows_build_number(right)
    if left_build is None or right_build is None:
        return compare_versions(left, right)
    if left_build != right_build:
        return -1 if left_build < right_build else 1
    left_ubr = windows_ubr(left)
    right_ubr = windows_ubr(right)
    if left_ubr is None or right_ubr is None:
        return 0
    if left_ubr != right_ubr:
        return -1 if left_ubr < right_ubr else 1
    return 0


def windows_build_number(value: str) -> int | None:
    """Return the Windows OS build number when the value looks like one."""
    parts = parse_numeric_version(value)
    if len(parts) >= 3 and tuple(parts[:2]) in _WINDOWS_PREFIXES:
        return parts[2]
    if len(parts) in {1, 2} and parts[0] >= 10000:
        return parts[0]
    return None


def windows_ubr(value: str) -> int | None:
    """Return the update build revision when present."""
    parts = parse_numeric_version(value)
    if len(parts) >= 4 and tuple(parts[:2]) in _WINDOWS_PREFIXES:
        return parts[3]
    if len(parts) == 2 and parts[0] >= 10000:
        return parts[1]
    return None


def _cmp_tuples(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    if left < right:
        return -1
    if left > right:
        return 1
    return 0


def align_version_tuples(
    left: tuple[int, ...], right: tuple[int, ...]
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    """Align tuples, stripping a well-known Windows NT prefix when lengths differ."""
    if len(left) == len(right):
        return left, right
    shorter, longer = (left, right) if len(left) < len(right) else (right, left)
    extra = len(longer) - len(shorter)
    prefix = tuple(longer[:extra])
    if prefix in _WINDOWS_PREFIXES:
        stripped = tuple(longer[extra:])
        if len(left) < len(right):
            return shorter, stripped
        return stripped, shorter
    width = max(len(left), len(right))
    return left + (0,) * (width - len(left)), right + (0,) * (width - len(right))


def parse_version_range(text: str) -> tuple[VersionBound, ...]:
    """Parse `>=a <b`, `a - b`, or a single version as equality."""
    hyphen = _HYPHEN_RANGE.match(text)
    if hyphen is not None:
        return (
            VersionBound(">=", hyphen.group(1).lstrip("vV")),
            VersionBound("<=", hyphen.group(2).lstrip("vV")),
        )
    bounds: list[VersionBound] = []
    for match in _RANGE_TOKEN.finditer(text):
        operator = match.group(1) or "=="
        if operator == "=":
            operator = "=="
        bounds.append(VersionBound(operator, match.group(2)))
    if not bounds:
        raise ValueError(f"unparsed version range: {text}")
    return tuple(bounds)


def version_in_range(version: str, range_text: str, *, windows: bool = False) -> bool:
    """Return whether `version` satisfies every bound in `range_text`."""
    compare = compare_windows_versions if windows else compare_versions
    for bound in parse_version_range(range_text):
        cmp = compare(version, bound.version)
        if bound.op == ">=" and cmp < 0:
            return False
        if bound.op == ">" and cmp <= 0:
            return False
        if bound.op == "<=" and cmp > 0:
            return False
        if bound.op == "<" and cmp >= 0:
            return False
        if bound.op == "==" and cmp != 0:
            return False
    return True


def same_windows_build_family(inventory_build: str, listed_build: str) -> bool:
    """Return whether a short listed build (e.g. 22621) matches an inventory build."""
    inventory = parse_numeric_version(inventory_build)
    listed = parse_numeric_version(listed_build)
    if len(listed) == 1:
        if len(inventory) >= 3:
            return inventory[2] == listed[0]
        if len(inventory) == 2:
            return inventory[0] == listed[0]
        return inventory[0] == listed[0]
    return compare_versions(inventory_build, listed_build) == 0
