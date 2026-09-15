"""GitHub Issues change-record store. Uses a scripted transport; no live API."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from findupdates.changerecords import (
    ChangeRecord,
    ChangeStoreError,
    GitHubChangeStore,
    LifecycleState,
    github_token,
    record_to_dict,
    render_github_issue,
    store_from_env,
)
from findupdates.changerecords.__main__ import main
from findupdates.changerecords.github import MappingIssuesTransport
from findupdates.changerecords.serialize import issue_body
from findupdates.changerecords.store import with_github_issue

NOW = datetime(2026, 9, 15, 18, tzinfo=UTC)
REPO = "acme/lab"
TOKEN = "test-token-value-not-a-github-pat"
COLLECTION = "https://api.github.com/repos/acme/lab/issues"
ITEM = f"{COLLECTION}/7"


def _record() -> ChangeRecord:
    return ChangeRecord(
        change_id="change-id_aaaaaaaaaaaaaaaaaa",
        idempotency_key="change_aaaaaaaaaaaaaaaaaaaa",
        lifecycle=LifecycleState.AWAITING_APPROVAL,
        advisory_ids=("ADV-1",),
        device_ids=("SYNTHETIC-MED-001",),
        deployment_group="lab-ring-0",
        risk_score=61,
        severity="HIGH",
        policy_result="REQUIRE_APPROVAL",
        vendor="microsoft",
        evidence_links=("advisory:ADV-1",),
        validation_plan="Run lab validation.",
        rollout_plan="lab then canary",
        overrides=(),
        github_issue_number=None,
        updated_at=NOW,
    )


def _issue_json(number: int, body: str) -> bytes:
    return json.dumps(
        {"number": number, "body": body, "labels": [{"name": "findupdates-change"}]}
    ).encode()


class GitHubChangeStoreTests(unittest.TestCase):
    def test_create_then_update_same_issue(self) -> None:
        record = _record()
        stamped = with_github_issue(record, 7)
        issue_list = json.dumps([json.loads(_issue_json(7, issue_body(stamped)))]).encode()
        transport = MappingIssuesTransport(
            scripts={
                f"GET {COLLECTION}": [
                    (200, b"[]"),
                    (200, issue_list),
                    (200, issue_list),
                ],
                f"POST {COLLECTION}": [(201, b'{"number":7}')],
                f"PATCH {ITEM}": [(200, b'{"number":7}'), (200, b'{"number":7}')],
            }
        )
        store = GitHubChangeStore(repository=REPO, token=TOKEN, transport=transport, max_retries=0)
        created = store.upsert(record)
        updated = store.upsert(record)
        self.assertTrue(created.created)
        self.assertFalse(updated.created)
        self.assertEqual(created.issue_number, 7)
        self.assertEqual(updated.issue_number, 7)
        methods = [item[0] for item in transport.calls]
        self.assertEqual(methods, ["GET", "POST", "PATCH", "GET", "PATCH"])
        self.assertTrue(all(transport.authorized))
        for _method, _url, body in transport.calls:
            if body is None:
                continue
            payload = json.loads(body)
            self.assertNotIn("token", payload)
            self.assertNotIn(TOKEN, body.decode("utf-8"))
            rendered = render_github_issue(record)
            self.assertNotIn("token", rendered)
        loaded = store.get(record.idempotency_key)
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.github_issue_number, 7)
        self.assertEqual(loaded.policy_result, "REQUIRE_APPROVAL")

    def test_duplicate_issues_fail_closed(self) -> None:
        record = _record()
        body = issue_body(with_github_issue(record, 7))
        transport = MappingIssuesTransport(
            scripts={
                f"GET {COLLECTION}": [
                    (
                        200,
                        json.dumps(
                            [
                                json.loads(_issue_json(7, body)),
                                json.loads(_issue_json(8, body)),
                            ]
                        ).encode(),
                    )
                ]
            }
        )
        store = GitHubChangeStore(repository=REPO, token=TOKEN, transport=transport, max_retries=0)
        with self.assertRaises(ChangeStoreError):
            store.upsert(record)
        self.assertEqual([item[0] for item in transport.calls], ["GET"])

    def test_malformed_body_fails_closed(self) -> None:
        record = _record()
        transport = MappingIssuesTransport(
            scripts={
                f"GET {COLLECTION}": [
                    (200, json.dumps([{"number": 7, "body": "not a change record"}]).encode())
                ]
            }
        )
        store = GitHubChangeStore(repository=REPO, token=TOKEN, transport=transport, max_retries=0)
        with self.assertRaises(ChangeStoreError):
            store.get(record.idempotency_key)

    def test_auth_failure_does_not_upsert(self) -> None:
        transport = MappingIssuesTransport(
            scripts={f"GET {COLLECTION}": [(401, b'{"message":"bad"}')]}
        )
        store = GitHubChangeStore(repository=REPO, token=TOKEN, transport=transport, max_retries=0)
        with self.assertRaises(ChangeStoreError) as raised:
            store.upsert(_record())
        self.assertIn("authentication", str(raised.exception).lower())

    def test_missing_token_and_repo_fail_closed(self) -> None:
        self.assertIsNone(github_token({}))
        with self.assertRaises(ChangeStoreError):
            store_from_env(repository=REPO, environ={})
        with self.assertRaises(ChangeStoreError):
            GitHubChangeStore(repository="not a repo", token=TOKEN)

    def test_cli_dry_run_and_missing_token(self) -> None:
        record = _record()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "record.json"
            path.write_text(json.dumps(record_to_dict(record)), encoding="utf-8")
            self.assertEqual(main(["upsert", str(path), "--dry-run"], environ={}), 0)
            self.assertEqual(
                main(["upsert", str(path), "--repository", REPO], environ={}),
                1,
            )


if __name__ == "__main__":
    unittest.main()
