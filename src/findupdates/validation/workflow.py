"""CLI used by GitHub Actions. Outcome is read from the result file, not from flags."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from findupdates.changerecords.models import PromotionDenied
from findupdates.validation.gates import assert_validation_gate
from findupdates.validation.serialize import dict_to_result


def main(argv: list[str] | None = None) -> int:
    """Fail closed if stored validation evidence forbids promotion."""
    parser = argparse.ArgumentParser(description="FindUpdates validation promotion gate")
    parser.add_argument("result_json", type=Path)
    parser.add_argument("target_environment", choices=("lab", "canary", "production"))
    args = parser.parse_args(argv)
    payload = json.loads(args.result_json.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit("validation result JSON must be an object")
    result = dict_to_result(payload)
    try:
        assert_validation_gate(result, args.target_environment)
    except PromotionDenied as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
