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
    intel_csaf_index_url: str | None = None
    intel_lookback_days: int = 45
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    enrichment_cache_max_age_hours: int = 24
    ai_enabled: bool = False
    ai_provider: str = "offline"
    copilot_model: str = "claude-haiku-4.5"
    copilot_max_completions: int = 8
    copilot_timeout_seconds: float = 60.0
    checkpoint_dir: str = ".findupdates/checkpoints"
    collection_output_dir: str | None = None
    github_repository: str | None = None

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
            msrc_lookback_days=_lookback_days("FINDUPDATES_MSRC_LOOKBACK_DAYS", 45),
            intel_csaf_index_url=os.getenv("FINDUPDATES_INTEL_CSAF_INDEX_URL") or None,
            intel_lookback_days=_lookback_days("FINDUPDATES_INTEL_LOOKBACK_DAYS", 45),
            nvd_base_url=os.getenv(
                "FINDUPDATES_NVD_BASE_URL",
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
            ),
            kev_url=os.getenv(
                "FINDUPDATES_KEV_URL",
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            ),
            enrichment_cache_max_age_hours=int(
                os.getenv("FINDUPDATES_ENRICHMENT_CACHE_MAX_AGE_HOURS", "24")
            ),
            ai_enabled=_bool_env("FINDUPDATES_AI_ENABLED", False),
            ai_provider=os.getenv("FINDUPDATES_AI_PROVIDER", "offline").strip().lower()
            or "offline",
            copilot_model=os.getenv("FINDUPDATES_COPILOT_MODEL", "claude-haiku-4.5").strip()
            or "claude-haiku-4.5",
            copilot_max_completions=_positive_int("FINDUPDATES_COPILOT_MAX_COMPLETIONS", 8),
            copilot_timeout_seconds=float(os.getenv("FINDUPDATES_COPILOT_TIMEOUT_SECONDS", "60")),
            checkpoint_dir=os.getenv("FINDUPDATES_CHECKPOINT_DIR", ".findupdates/checkpoints"),
            collection_output_dir=os.getenv("FINDUPDATES_COLLECTION_OUTPUT_DIR") or None,
            github_repository=os.getenv("FINDUPDATES_GITHUB_REPOSITORY") or None,
        )


def _lookback_days(name: str, default: int) -> int:
    return _positive_int(name, default)


def _positive_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    value = int(raw)
    if value < 1:
        raise ValueError(f"{name} must be >= 1")
    return value


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}
