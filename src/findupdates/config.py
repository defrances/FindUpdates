"""Runtime configuration loaded from environment variables only."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Settings:
    """Non-secret runtime settings.

    Secrets belong in environment-specific secret stores and must not be represented
    as committed configuration fields.
    """

    environment: str = "local"
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> Settings:
        """Build settings from the process environment."""
        return cls(
            environment=os.getenv("FINDUPDATES_ENVIRONMENT", "local"),
            log_level=os.getenv("FINDUPDATES_LOG_LEVEL", "INFO").upper(),
        )
