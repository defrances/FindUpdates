"""AI providers. The only allowed capability is returning a JSON object."""

from __future__ import annotations

from typing import Protocol

from findupdates.agents.models import (
    TEMPLATE_VERSION,
    AgentRole,
    ClaimKind,
    ModelIdentity,
)


class ProviderUnavailableError(RuntimeError):
    """Raised when a configured model provider cannot be reached."""


class AgentProvider(Protocol):
    """Non-authoritative completion interface. No deploy or approve tools."""

    identity: ModelIdentity

    def complete(self, payload: dict[str, object]) -> dict[str, object]:
        """Return a JSON-like mapping. Must not mutate authoritative input."""


class OfflineProvider:
    """Deterministic template provider used in CI and as the unavailable fallback."""

    identity = ModelIdentity("offline", "template", TEMPLATE_VERSION)

    def complete(self, payload: dict[str, object]) -> dict[str, object]:
        """Build review text only from structured evidence and authoritative facts."""
        evidence = {
            str(item["evidence_id"]): str(item["value"])
            for item in _as_objects(payload.get("evidence"))
            if "evidence_id" in item and "value" in item
        }
        authoritative = _as_object(payload.get("authoritative"))
        policy = str(authoritative.get("policy_result", "HOLD"))
        verdict = str(authoritative.get("applicability_verdict", "unknown"))
        claims = [
            _claim(
                "c-title",
                ClaimKind.FACT,
                f"Advisory title is {evidence.get('ev-advisory-title', 'unspecified')}.",
                "ev-advisory-title",
            ),
            _claim(
                "c-verdict",
                ClaimKind.FACT,
                f"Deterministic applicability verdict is {verdict}.",
                "ev-applicability-verdict",
            ),
            _claim(
                "c-policy",
                ClaimKind.FACT,
                f"Deterministic policy result is {policy}.",
                "ev-policy-result",
            ),
            _claim(
                "c-score",
                ClaimKind.FACT,
                (
                    "Numeric risk score is "
                    f"{authoritative.get('risk_score')} "
                    f"({authoritative.get('risk_severity')})."
                ),
                "ev-risk-score",
            ),
        ]
        if "ev-reboot" in evidence:
            claims.append(
                _claim(
                    "c-reboot",
                    ClaimKind.FACT,
                    f"Reboot requirement is {evidence['ev-reboot']}.",
                    "ev-reboot",
                )
            )
        if "ev-applicability-missing" in evidence:
            claims.append(
                _claim(
                    "c-missing",
                    ClaimKind.INFERENCE,
                    (
                        "Applicability reported missing data: "
                        f"{evidence['ev-applicability-missing']}."
                    ),
                    "ev-applicability-missing",
                )
            )
        planning = _planning_summary(policy)
        return {
            "confidence": "low",
            "needs_human_review": policy != "ALLOW_ANALYSIS" or verdict == "unknown",
            "claims": claims,
            "sections": [
                {
                    "role": AgentRole.UPDATE_INTELLIGENCE.value,
                    "summary": (
                        "Structured vendor fields: "
                        f"category={evidence.get('ev-category', 'unknown')}, "
                        f"reboot={evidence.get('ev-reboot', 'unknown')}, "
                        f"packages={evidence.get('ev-packages', 'none')}."
                    ),
                    "claim_ids": ["c-title", "c-reboot"]
                    if "ev-reboot" in evidence
                    else ["c-title"],
                    "needs_human_review": "ev-known-issues" in evidence,
                },
                {
                    "role": AgentRole.APPLICABILITY_REVIEW.value,
                    "summary": (
                        f"Matcher verdict={verdict} "
                        f"confidence={authoritative.get('applicability_confidence')}."
                    ),
                    "claim_ids": ["c-verdict"]
                    + (["c-missing"] if "ev-applicability-missing" in evidence else []),
                    "needs_human_review": verdict in {"unknown", "possibly_affected"},
                },
                {
                    "role": AgentRole.RISK_EXPLANATION.value,
                    "summary": (
                        f"Score {authoritative.get('risk_score')} "
                        f"{authoritative.get('risk_severity')} leads to {policy}."
                    ),
                    "claim_ids": ["c-score", "c-policy"],
                    "needs_human_review": True,
                },
                {
                    "role": AgentRole.CHANGE_PLANNING.value,
                    "summary": planning,
                    "claim_ids": ["c-policy"],
                    "needs_human_review": True,
                },
            ],
        }


class ScriptedProvider:
    """Test double that returns a caller-supplied payload and cannot execute tools."""

    def __init__(
        self, payload: dict[str, object], *, identity: ModelIdentity | None = None
    ) -> None:
        self._payload = payload
        self.identity = identity or ModelIdentity("scripted", "fixture", "test")

    def complete(self, payload: dict[str, object]) -> dict[str, object]:
        del payload
        return dict(self._payload)


class UnavailableProvider:
    """Test/production stand-in for a down or unconfigured model endpoint."""

    identity = ModelIdentity("none", "unavailable", "0")

    def complete(self, payload: dict[str, object]) -> dict[str, object]:
        del payload
        raise ProviderUnavailableError("model provider is unavailable")


def _planning_summary(policy: str) -> str:
    if policy in {"BLOCK", "HOLD"}:
        return (
            "Do not plan production rollout. Policy is "
            f"{policy}; keep the change in review until gates clear."
        )
    if policy == "REQUIRE_APPROVAL":
        return (
            "Propose validation scope and monitoring checks. Human approval is "
            "required before any deployment adapter is used."
        )
    if policy == "REQUIRE_VALIDATION":
        return "Propose lab validation cases before requesting approval."
    return "Analysis only. This result does not authorize deployment."


def _claim(claim_id: str, kind: ClaimKind, text: str, evidence_id: str) -> dict[str, object]:
    return {
        "claim_id": claim_id,
        "kind": kind.value,
        "text": text,
        "evidence_ids": [evidence_id],
    }


def _as_objects(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _as_object(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}
