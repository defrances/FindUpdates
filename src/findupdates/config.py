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
    http_timeout_seconds: float = 30.0
    http_max_retries: int = 3
    http_min_interval_seconds: float = 0.25
    msrc_base_url: str = "https://api.msrc.microsoft.com/cvrf/v3.0"
    msrc_lookback_days: int = 45

    @classmethod
    def from_env(cls) -> Settings:
        """Build settings from the process environment."""
        return cls(
            environment=os.getenv("FINDUPDATES_ENVIRONMENT", "local"),
            log_level=os.getenv("FINDUPDATES_LOG_LEVEL", "INFO").upper(),
            http_timeout_seconds=float(os.getenv("FINDUPDATES_HTTP_TIMEOUT_SECONDS", "30")),
            http_max_retries=int(os.getenv("FINDUPDATES_HTTP_MAX_RETRIES", "3")),
            http_min_interval_seconds=float(
                os.getenv("FINDUPDATES_HTTP_MIN_INTERVAL_SECONDS", "0.25")
            ),
            msrc_base_url=os.getenv(
                "FINDUPDATES_MSRC_BASE_URL", "https://api.msrc.microsoft.com/cvrf/v3.0"
            ),
            msrc_lookback_days=int(os.getenv("FINDUPDATES_MSRC_LOOKBACK_DAYS", "45")),
        )
