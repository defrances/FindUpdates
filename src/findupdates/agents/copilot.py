"""GitHub Copilot CLI provider. JSON-only complete; no deploy or approve tools."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol

from findupdates.agents.models import ModelIdentity
from findupdates.agents.prompts import OUTPUT_HINT, SYSTEM_PROMPT
from findupdates.agents.provider import AgentProvider, ProviderUnavailableError
from findupdates.config import Settings

COPILOT_PROVIDERS = frozenset({"copilot", "github-copilot", "github_copilot"})
DEFAULT_COPILOT_MODEL = "claude-haiku-4.5"
_TOKEN_VARS = ("COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN")
_FORBIDDEN_FLAGS = ("--yolo", "--allow-all", "--allow-all-tools", "--allow-all-paths")


class CopilotCommandRunner(Protocol):
    """Test seam for Copilot CLI without spawning a real process."""

    def run(
        self, args: list[str], *, timeout: float, env: Mapping[str, str]
    ) -> CopilotCommandResult: ...


@dataclass(frozen=True, slots=True)
class CopilotCommandResult:
    returncode: int
    stdout: str
    stderr: str = ""


@dataclass
class RecordingCopilotRunner:
    """Scripted Copilot CLI for unit tests."""

    results: list[CopilotCommandResult | BaseException] = field(default_factory=list)
    calls: list[tuple[list[str], float, tuple[str, ...]]] = field(default_factory=list)

    def run(
        self, args: list[str], *, timeout: float, env: Mapping[str, str]
    ) -> CopilotCommandResult:
        present = tuple(name for name in _TOKEN_VARS if env.get(name, "").strip())
        self.calls.append((list(args), timeout, present))
        if not self.results:
            raise ProviderUnavailableError("scripted copilot runner is exhausted")
        outcome = self.results.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class SubprocessCopilotRunner:
    """Spawn `copilot` with argv only. Tokens stay in the environment."""

    def run(
        self, args: list[str], *, timeout: float, env: Mapping[str, str]
    ) -> CopilotCommandResult:
        binary = shutil.which("copilot")
        if binary is None:
            raise ProviderUnavailableError("copilot CLI is not installed")
        try:
            completed = subprocess.run(  # noqa: S603
                [binary, *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                env=dict(env),
                check=False,
            )
        except FileNotFoundError as exc:
            raise ProviderUnavailableError("copilot CLI is not installed") from exc
        except subprocess.TimeoutExpired as exc:
            raise ProviderUnavailableError("copilot CLI timed out") from exc
        except OSError as exc:
            raise ProviderUnavailableError("copilot CLI could not be started") from exc
        return CopilotCommandResult(
            returncode=int(completed.returncode),
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )


class CopilotProvider:
    """Non-authoritative Copilot completion. Tools, yolo, and tokens are forbidden."""

    def __init__(
        self,
        *,
        model: str = DEFAULT_COPILOT_MODEL,
        timeout_seconds: float = 60.0,
        runner: CopilotCommandRunner | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        if not model.strip():
            raise ValueError("copilot model must not be empty")
        if timeout_seconds <= 0:
            raise ValueError("copilot timeout_seconds must be positive")
        self.identity = ModelIdentity("github-copilot", model.strip(), "cli")
        self._model = model.strip()
        self._timeout = timeout_seconds
        self._runner = runner or SubprocessCopilotRunner()
        self._environ = environ
        self._dead: str | None = None

    @classmethod
    def from_settings(cls, settings: Settings) -> CopilotProvider:
        """Build from runtime settings. Tokens are read from the process environment."""
        return cls(
            model=settings.copilot_model,
            timeout_seconds=settings.copilot_timeout_seconds,
        )

    def complete(self, payload: dict[str, object]) -> dict[str, object]:
        """Return Copilot JSON or raise so the caller can use the offline template."""
        if self._dead is not None:
            raise ProviderUnavailableError(self._dead)
        try:
            return self._complete(payload)
        except ProviderUnavailableError as exc:
            self._dead = str(exc) or "copilot provider unavailable"
            raise

    def _complete(self, payload: dict[str, object]) -> dict[str, object]:
        env = dict(os.environ if self._environ is None else self._environ)
        if not any(env.get(name, "").strip() for name in _TOKEN_VARS):
            raise ProviderUnavailableError("copilot token is not configured")
        env.setdefault("COPILOT_AUTO_UPDATE", "false")
        prompt = render_copilot_prompt(payload)
        args = copilot_argv(prompt, self._model)
        _assert_safe_argv(args)
        try:
            result = self._runner.run(args, timeout=self._timeout, env=env)
        except ProviderUnavailableError:
            raise
        except (FileNotFoundError, TimeoutError, OSError) as exc:
            raise ProviderUnavailableError("copilot CLI could not be started") from exc
        if result.returncode != 0:
            raise ProviderUnavailableError("copilot CLI exited unsuccessfully")
        return parse_copilot_output(result.stdout)


class CompletionBudget:
    """Limit live Copilot calls; remaining analyses use the offline fallback."""

    def __init__(self, inner: AgentProvider, limit: int) -> None:
        if limit < 1:
            raise ValueError("copilot completion budget must be >= 1")
        self._inner = inner
        self._remaining = limit
        self.identity = inner.identity

    def complete(self, payload: dict[str, object]) -> dict[str, object]:
        if self._remaining <= 0:
            raise ProviderUnavailableError("copilot completion budget exhausted")
        result = self._inner.complete(payload)
        self._remaining -= 1
        return result


def copilot_argv(prompt: str, model: str) -> list[str]:
    """Build Copilot CLI args. Never includes a token or an allow-all flag."""
    return [
        "-p",
        prompt,
        "-s",
        "--output-format=json",
        "--no-ask-user",
        "--available-tools=",
        "--disable-builtin-mcps",
        "--deny-tool=shell",
        "--deny-tool=write",
        "--deny-tool=read",
        "--deny-tool=url",
        "--deny-tool=memory",
        f"--model={model}",
        "--secret-env-vars=COPILOT_GITHUB_TOKEN,GH_TOKEN,GITHUB_TOKEN",
    ]


def render_copilot_prompt(payload: dict[str, object]) -> str:
    """Ask Copilot for one analysis JSON object. Vendor text is data, not commands."""
    system = str(payload.get("system_prompt") or SYSTEM_PROMPT)
    return (
        f"{system}\n\n"
        "Output a single JSON object only. No markdown fences. Schema hint:\n"
        f"{json.dumps(OUTPUT_HINT, ensure_ascii=True)}\n\n"
        "User JSON:\n"
        f"{json.dumps(payload, ensure_ascii=True, sort_keys=True)}"
    )


def parse_copilot_output(stdout: str) -> dict[str, object]:
    """Accept a JSON object or Copilot JSONL wrapping that object."""
    text = stdout.strip()
    if not text:
        raise ProviderUnavailableError("copilot returned empty output")
    candidates: list[dict[str, object]] = []
    direct = _load_object(text)
    if direct is not None:
        nested = _unwrap_analysis(direct)
        if nested is not None:
            return nested
        candidates.append(direct)
    chunks: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        item = _load_object(stripped)
        if item is None:
            chunks.append(stripped)
            continue
        nested = _unwrap_analysis(item)
        if nested is not None:
            return nested
        candidates.append(item)
        content = _assistant_content(item)
        if content:
            chunks.append(content)
    blob = _strip_fence("\n".join(chunks) if chunks else text)
    loaded = _load_object(blob)
    if loaded is not None:
        nested = _unwrap_analysis(loaded)
        if nested is not None:
            return nested
        return loaded
    if candidates:
        return candidates[-1]
    raise ProviderUnavailableError("copilot did not return a JSON object")


def _unwrap_analysis(item: dict[str, object]) -> dict[str, object] | None:
    if "claims" in item or "sections" in item:
        return item
    content = _assistant_content(item)
    if not content:
        return None
    nested = _load_object(content)
    if nested is not None and ("claims" in nested or "sections" in nested):
        return nested
    return nested


def _assert_safe_argv(args: list[str]) -> None:
    for item in args:
        lowered = item.casefold()
        for flag in _FORBIDDEN_FLAGS:
            if lowered == flag or lowered.startswith(f"{flag}="):
                raise ProviderUnavailableError("copilot argv must not enable unrestricted tools")
        if _looks_like_token(item):
            raise ProviderUnavailableError("copilot argv must not include a token")


def _looks_like_token(value: str) -> bool:
    lowered = value.casefold()
    if lowered.startswith("bearer "):
        return True
    return value.startswith(("ghp_", "gho_", "ghu_", "ghs_", "github_pat_"))


def _load_object(text: str) -> dict[str, object] | None:
    try:
        loaded = json.loads(_strip_fence(text))
    except json.JSONDecodeError:
        return None
    return loaded if isinstance(loaded, dict) else None


def _assistant_content(item: dict[str, object]) -> str:
    for key in ("content", "text", "message"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value
    data = item.get("data")
    if isinstance(data, dict):
        for key in ("content", "text"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return ""


def _strip_fence(text: str) -> str:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()
