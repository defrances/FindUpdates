"""GitHub Issues API errors for the change-record store."""

from __future__ import annotations


class ChangeStoreError(RuntimeError):
    """Raised when GitHub cannot be used as the change-record system of record."""
