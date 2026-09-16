from __future__ import annotations

import json
import unittest

from findupdates.agents import analyze
from findupdates.agents.copilot import (
    CompletionBudget,
    CopilotCommandResult,
    CopilotProvider,
    RecordingCopilotRunner,
    copilot_argv,
    parse_copilot_output,
)
from findupdates.agents.provider import ProviderUnavailableError
from findupdates.agents.run import default_provider
from findupdates.applicability import evaluate
from findupdates.config import Settings
from findupdates.mvp.fixtures import NOW, imaging_workstation, microsoft_advisory
from findupdates.pipeline.detect import _detect_ai_settings
from findupdates.risk import assess as assess_risk


def _analysis_json() -> dict[str, object]:
    return {
        "confidence": "low",
        "needs_human_review": True,
        "claims": [
            {
                "claim_id": "c-title",
                "kind": "fact",
                "text": "Advisory title is taken from structured evidence.",
                "evidence_ids": ["ev-advisory-title"],
            }
        ],
        "sections": [
            {
                "role": "update_intelligence",
                "summary": "Vendor fields were copied from structured evidence.",
                "claim_ids": ["c-title"],
                "needs_human_review": True,
            },
            {
                "role": "applicability_review",
                "summary": "Applicability remains the deterministic matcher result.",
                "claim_ids": ["c-title"],
                "needs_human_review": True,
            },
            {
                "role": "risk_explanation",
                "summary": "Risk score and policy remain the deterministic engine result.",
                "claim_ids": ["c-title"],
                "needs_human_review": True,
            },
            {
                "role": "change_planning",
                "summary": "No deployment is authorized by this analysis.",
                "claim_ids": ["c-title"],
                "needs_human_review": True,
            },
        ],
    }


class CopilotProviderTests(unittest.TestCase):
    def test_argv_is_toolless_and_has_no_token(self) -> None:
        args = copilot_argv("summarize this advisory", "claude-haiku-4.5")
        blob = " ".join(args)
        self.assertNotIn("--yolo", blob)
        self.assertNotIn("--allow-all", blob)
        self.assertIn("--available-tools=", args)
        self.assertIn("--deny-tool=shell", args)
        self.assertNotIn("ghp_secret", blob)
        self.assertEqual(args[args.index("-p") + 1], "summarize this advisory")

    def test_scripted_json_is_returned_without_logging_token(self) -> None:
        payload = _analysis_json()
        runner = RecordingCopilotRunner(results=[CopilotCommandResult(0, json.dumps(payload))])
        provider = CopilotProvider(
            runner=runner,
            environ={"GITHUB_TOKEN": "ghs_unit-test-token"},
        )
        result = provider.complete({"notice": "data only"})
        self.assertEqual(result["claims"], payload["claims"])
        args, _timeout, present = runner.calls[0]
        self.assertEqual(present, ("GITHUB_TOKEN",))
        self.assertNotIn("ghs_unit-test-token", " ".join(args))
        self.assertNotIn("--yolo", args)

    def test_missing_token_does_not_spawn_cli(self) -> None:
        runner = RecordingCopilotRunner(
            results=[CopilotCommandResult(0, json.dumps(_analysis_json()))]
        )
        provider = CopilotProvider(runner=runner, environ={})
        with self.assertRaises(ProviderUnavailableError):
            provider.complete({"notice": "data only"})
        self.assertEqual(runner.calls, [])

    def test_hard_failure_is_cached(self) -> None:
        runner = RecordingCopilotRunner(
            results=[
                CopilotCommandResult(127, ""),
                CopilotCommandResult(0, json.dumps(_analysis_json())),
            ]
        )
        provider = CopilotProvider(runner=runner, environ={"GITHUB_TOKEN": "unit"})
        with self.assertRaises(ProviderUnavailableError):
            provider.complete({"notice": "data only"})
        with self.assertRaises(ProviderUnavailableError):
            provider.complete({"notice": "data only"})
        self.assertEqual(len(runner.calls), 1)

    def test_completion_budget_falls_back_after_cap(self) -> None:
        runner = RecordingCopilotRunner(
            results=[
                CopilotCommandResult(0, json.dumps(_analysis_json())),
                CopilotCommandResult(0, json.dumps(_analysis_json())),
            ]
        )
        inner = CopilotProvider(runner=runner, environ={"GITHUB_TOKEN": "unit"})
        provider = CompletionBudget(inner, 1)
        self.assertTrue(provider.complete({"notice": "first"}))
        with self.assertRaises(ProviderUnavailableError):
            provider.complete({"notice": "second"})
        self.assertEqual(len(runner.calls), 1)

    def test_bound_copilot_json_cannot_change_policy(self) -> None:
        advisory = microsoft_advisory()
        device = imaging_workstation()
        app = evaluate(advisory, device, now=NOW)
        risk = assess_risk(advisory, device, app, now=NOW)
        runner = RecordingCopilotRunner(
            results=[CopilotCommandResult(0, json.dumps(_analysis_json()))]
        )
        result = analyze(
            advisory,
            device,
            app,
            risk,
            now=NOW,
            provider=CopilotProvider(runner=runner, environ={"GITHUB_TOKEN": "unit"}),
        )
        self.assertEqual(result.authoritative.policy_result, risk.policy_result.value)
        self.assertEqual(result.model.provider, "github-copilot")
        self.assertFalse(result.used_fallback)

    def test_jsonl_and_fenced_output_parse(self) -> None:
        inner = json.dumps(_analysis_json())
        jsonl = json.dumps({"type": "assistant.message", "data": {"content": inner}})
        self.assertEqual(parse_copilot_output(jsonl)["claims"][0]["claim_id"], "c-title")
        fenced = "```json\n" + inner + "\n```\n"
        self.assertEqual(parse_copilot_output(fenced)["needs_human_review"], True)

    def test_default_provider_selects_copilot(self) -> None:
        provider = default_provider(Settings(ai_enabled=True, ai_provider="copilot"))
        self.assertEqual(provider.identity.provider, "github-copilot")
        self.assertEqual(provider.identity.name, "claude-haiku-4.5")

    def test_detect_honors_disabled_ai_and_forces_unknown_offline(self) -> None:
        disabled = _detect_ai_settings(Settings(ai_enabled=False, ai_provider="copilot"))
        self.assertFalse(disabled.ai_enabled)
        self.assertEqual(disabled.ai_provider, "offline")
        copilot = _detect_ai_settings(Settings(ai_enabled=True, ai_provider="copilot"))
        self.assertTrue(copilot.ai_enabled)
        self.assertEqual(copilot.ai_provider, "copilot")
        unknown = _detect_ai_settings(Settings(ai_enabled=True, ai_provider="openai"))
        self.assertEqual(unknown.ai_provider, "offline")


if __name__ == "__main__":
    unittest.main()
