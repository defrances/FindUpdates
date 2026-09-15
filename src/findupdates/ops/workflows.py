"""Static checks for least-privilege, pinned Actions and untrusted-PR isolation."""

from __future__ import annotations

import re
from pathlib import Path

_USES = re.compile(r"uses:\s+(\S+)")
_SHA = re.compile(r"^[0-9a-f]{40}$")


def action_pins(workflow: str) -> tuple[str, ...]:
    return tuple(match.group(1) for match in _USES.finditer(workflow))


def unpinned_actions(workflow: str) -> tuple[str, ...]:
    bad: list[str] = []
    for ref in action_pins(workflow):
        if "@" not in ref:
            bad.append(ref)
            continue
        spec = ref.rsplit("@", 1)[1]
        if not _SHA.fullmatch(spec):
            bad.append(ref)
    return tuple(bad)


def has_pull_request_trigger(workflow: str) -> bool:
    return bool(
        re.search(r"(?m)^on:\s*$", workflow) and re.search(r"(?m)^\s+pull_request:", workflow)
    )


def workflow_has_contents_read(workflow: str) -> bool:
    return "contents: read" in workflow


def load_workflow(root: Path, name: str) -> str:
    return (root / ".github" / "workflows" / name).read_text(encoding="utf-8")
