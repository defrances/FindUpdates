"""CLI used by GitHub Actions. Policy is read from the record, not from flags."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from findupdates.changerecords.models import PromotionDenied
from findupdates.changerecords.promote import assert_workflow_gate
from findupdates.changerecords.serialize import dict_to_record


def main(argv: list[str] | None = None) -> int:
    """Fail closed if the stored policy forbids the requested environment."""
    parser = argparse.ArgumentParser(description="FindUpdates change-record promotion gate")
    parser.add_argument("record_json", type=Path)
    parser.add_argument("target_environment", choices=("lab", "canary", "production"))
    args = parser.parse_args(argv)
    payload = json.loads(args.record_json.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit("change record JSON must be an object")
    if "policy_result" not in payload:
        raise SystemExit("change record is missing policy_result")
    record = dict_to_record(payload)
    try:
        assert_workflow_gate(record, args.target_environment)
    except PromotionDenied as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
