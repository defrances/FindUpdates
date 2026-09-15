"""CLI to upsert a change-record JSON file onto GitHub Issues. Does not deploy."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path

from findupdates.changerecords.errors import ChangeStoreError
from findupdates.changerecords.github import IssuesTransport, store_from_env
from findupdates.changerecords.serialize import dict_to_record
from findupdates.changerecords.store import render_github_issue
from findupdates.config import Settings
from findupdates.logging import configure_logging


def main(
    argv: list[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    transport: IssuesTransport | None = None,
) -> int:
    """Upsert one record. Dry-run prints the Issues payload and skips HTTP."""
    parser = argparse.ArgumentParser(
        prog="python -m findupdates.changerecords",
        description=(
            "Upsert a FindUpdates change record to GitHub Issues. "
            "This command never deploys updates. policy_result in the file is authoritative."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)
    upsert = sub.add_parser("upsert", help="Create or update the Issue for this idempotency key")
    upsert.add_argument("record_json", type=Path)
    upsert.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the Issues payload. No GitHub HTTP and no token required.",
    )
    upsert.add_argument(
        "--repository",
        default=None,
        help="owner/repo (FINDUPDATES_GITHUB_REPOSITORY).",
    )
    args = parser.parse_args(argv)
    settings = Settings.from_env()
    configure_logging(settings.log_level)
    payload = json.loads(args.record_json.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        print("change record JSON must be an object", file=sys.stderr)
        return 1
    try:
        record = dict_to_record(payload)
    except (KeyError, TypeError, ValueError) as exc:
        print(f"change record is invalid: {exc}", file=sys.stderr)
        return 1
    rendered = render_github_issue(record)
    if "token" in rendered:
        print("refusing to emit a payload that contains a token field", file=sys.stderr)
        return 1
    if args.dry_run:
        print(json.dumps({"title": rendered["title"], "labels": rendered["labels"]}, indent=2))
        print(rendered["body"])
        return 0
    repository = args.repository or settings.github_repository
    try:
        store = store_from_env(repository=repository, environ=environ, transport=transport)
        result = store.upsert(record)
    except ChangeStoreError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"issue={result.issue_number} created={str(result.created).lower()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
