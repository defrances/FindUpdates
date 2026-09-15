"""Resume interrupted deployments from a journal. Replays must not reinstall."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from findupdates.deployment.adapter import DeploymentAdapter
from findupdates.deployment.models import DeploymentRequest, DeploymentResult, OidcCredential
from findupdates.deployment.serialize import (
    dict_to_request,
    dict_to_result,
    request_to_dict,
    result_to_dict,
)


class DeploymentJournal:
    """Append-only request/result log used after a workflow crash."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._rows: list[tuple[DeploymentRequest, DeploymentResult]] = []
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                payload = json.loads(line)
                self._rows.append(
                    (dict_to_request(payload["request"]), dict_to_result(payload["result"]))
                )

    def record(self, request: DeploymentRequest, result: DeploymentResult) -> None:
        self._rows.append((request, result))
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {"request": request_to_dict(request), "result": result_to_dict(result)},
                    ensure_ascii=True,
                    sort_keys=True,
                )
                + "\n"
            )

    def latest(self, idempotency_key: str) -> DeploymentResult | None:
        for request, result in reversed(self._rows):
            if request.idempotency_key == idempotency_key:
                return result
        return None


def recover_or_deploy(
    adapter: DeploymentAdapter,
    journal: DeploymentJournal,
    request: DeploymentRequest,
    *,
    credential: OidcCredential,
    now: datetime,
) -> tuple[DeploymentResult, bool]:
    """Return the journaled result when present. Otherwise deploy once and journal."""
    prior = journal.latest(request.idempotency_key)
    if prior is not None:
        return prior, True
    result = adapter.deploy(request, credential=credential, now=now)
    journal.record(request, result)
    return result, False
