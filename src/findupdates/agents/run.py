"""Run bounded analysis agents without granting them safety authority."""

from __future__ import annotations

from datetime import datetime

from findupdates.agents.context import build_input
from findupdates.agents.copilot import (
    COPILOT_PROVIDERS,
    CompletionBudget,
    CopilotProvider,
)
from findupdates.agents.models import AgentAnalysis
from findupdates.agents.prompts import SYSTEM_PROMPT
from findupdates.agents.provider import (
    AgentProvider,
    OfflineProvider,
    ProviderUnavailableError,
    UnavailableProvider,
)
from findupdates.agents.validate import bind_analysis
from findupdates.applicability.models import ApplicabilityResult
from findupdates.config import Settings
from findupdates.ids import stable_id
from findupdates.inventory.models import DeviceInventory
from findupdates.normalization.models import UpdateAdvisory
from findupdates.risk.models import RiskAssessment


def analyze(
    advisory: UpdateAdvisory,
    device: DeviceInventory,
    applicability: ApplicabilityResult,
    risk: RiskAssessment,
    *,
    now: datetime,
    provider: AgentProvider | None = None,
    settings: Settings | None = None,
) -> AgentAnalysis:
    """Produce reviewer-facing analysis. Deterministic facts are not modified."""
    config = settings or Settings.from_env()
    agent_input = build_input(advisory, device, applicability, risk)
    fingerprint = input_fingerprint(agent_input.authoritative.advisory_id, device.device_id, risk)
    requested = provider or default_provider(config)
    used_fallback = False
    provider_available = True
    model = requested.identity
    payload = {"system_prompt": SYSTEM_PROMPT, **agent_input.provider_payload()}
    try:
        raw = requested.complete(payload)
        if not isinstance(raw, dict):
            raise ProviderUnavailableError("provider returned a non-object")
    except ProviderUnavailableError:
        raw = OfflineProvider().complete(payload)
        used_fallback = True
        provider_available = False
        model = OfflineProvider().identity
    return bind_analysis(
        raw,
        agent_input,
        model=model,
        used_fallback=used_fallback,
        provider_available=provider_available,
        fingerprint=fingerprint,
        generated_at=now,
    )


def default_provider(settings: Settings) -> AgentProvider:
    """Select the configured provider. Missing live models fail over to offline."""
    if not settings.ai_enabled:
        return UnavailableProvider()
    if settings.ai_provider in {"offline", "template"}:
        return OfflineProvider()
    if settings.ai_provider in COPILOT_PROVIDERS:
        return CompletionBudget(
            CopilotProvider.from_settings(settings),
            settings.copilot_max_completions,
        )
    return UnavailableProvider()


def input_fingerprint(advisory_id: str, device_id: str, risk: RiskAssessment) -> str:
    """Hash the analysis binding, including the deterministic risk fingerprint."""
    return stable_id(
        "agent-input",
        advisory_id,
        device_id,
        risk.assessment_id,
        risk.input_fingerprint,
        risk.policy_version,
    )
