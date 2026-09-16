"""Bounded AI analysis helpers outside the authoritative safety path."""

from findupdates.agents.brief import BriefSource, UpdateBriefing, brief_updates, briefing_to_dict
from findupdates.agents.copilot import CopilotProvider
from findupdates.agents.models import (
    PROMPT_VERSION,
    SCHEMA_VERSION,
    TEMPLATE_VERSION,
    AgentAnalysis,
    AgentRole,
    AnalysisConfidence,
    Claim,
    ClaimKind,
    ModelIdentity,
)
from findupdates.agents.provider import (
    OfflineProvider,
    ProviderUnavailableError,
    ScriptedProvider,
    UnavailableProvider,
)
from findupdates.agents.run import analyze, default_provider
from findupdates.agents.serialize import analysis_to_dict, canonical_analysis_json

__all__ = [
    "PROMPT_VERSION",
    "SCHEMA_VERSION",
    "TEMPLATE_VERSION",
    "AgentAnalysis",
    "AgentRole",
    "AnalysisConfidence",
    "Claim",
    "ClaimKind",
    "CopilotProvider",
    "ModelIdentity",
    "OfflineProvider",
    "ProviderUnavailableError",
    "ScriptedProvider",
    "UnavailableProvider",
    "BriefSource",
    "UpdateBriefing",
    "analyze",
    "analysis_to_dict",
    "brief_updates",
    "briefing_to_dict",
    "canonical_analysis_json",
    "default_provider",
]
