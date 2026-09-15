"""Detect credential-like material in committed operational files."""

from __future__ import annotations

import re
from pathlib import Path

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github_pat", re.compile(r"ghp_[A-Za-z0-9]{20,}")),
    ("github_pat_fine", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----")),
    ("phi", re.compile(r"(?i)\b(?:patient(?:[_\s-]?id)?|mrn)\b")),
)


def scan_text(value: str) -> tuple[str, ...]:
    """Return matcher names that fired."""
    return tuple(name for name, pattern in _PATTERNS if pattern.search(value))


def scan_paths(paths: tuple[Path, ...]) -> list[tuple[Path, str]]:
    """Scan committed operational files. Test fixtures are out of scope."""
    findings: list[tuple[Path, str]] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for name in scan_text(text):
            findings.append((path, name))
    return findings
