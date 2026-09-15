"""Verify package/artifact bytes against a declared SHA-256 digest."""

from __future__ import annotations

import hashlib
from pathlib import Path

from findupdates.deployment.models import PackageIdentity
from findupdates.ops.errors import IntegrityMismatch


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_digest(data: bytes, expected_sha256: str) -> None:
    digest = sha256_bytes(data)
    if digest != expected_sha256.lower():
        raise IntegrityMismatch("artifact digest does not match the expected SHA-256")


def verify_package(package: PackageIdentity, data: bytes) -> None:
    verify_digest(data, package.sha256)


def verify_file(path: Path, expected_sha256: str) -> None:
    verify_digest(path.read_bytes(), expected_sha256)
