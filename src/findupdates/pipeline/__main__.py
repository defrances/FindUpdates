"""CLI: assess collector output and upsert change records. Does not deploy."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from findupdates.changerecords.github import IssuesTransport
from findupdates.changerecords.store import ChangeRecordStore
from findupdates.config import Settings
from findupdates.logging import configure_logging
from findupdates.pipeline.assess import AssessOptions, assess_collected


def main(
    argv: list[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    transport: IssuesTransport | None = None,
    store: ChangeRecordStore | None = None,
) -> int:
    """Assess advisories against inventory. Dry-run skips GitHub HTTP."""
    parser = argparse.ArgumentParser(
        prog="python -m findupdates.pipeline",
        description=(
            "Assess collected advisory JSON against inventory and upsert change records. "
            "This command never deploys updates."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)
    assess = sub.add_parser(
        "assess",
        help="Evaluate applicability and risk, then upsert one record per advisory/group",
    )
    assess.add_argument(
        "--advisories",
        type=Path,
        required=True,
        help="Collector output directory or a single advisory JSON file.",
    )
    assess.add_argument(
        "--inventory",
        type=Path,
        required=True,
        help="Device inventory JSON (one device, a devices catalog, or an array).",
    )
    assess.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory for change-record JSON and summary.json.",
    )
    assess.add_argument(
        "--store",
        choices=("memory", "github"),
        default="memory",
        help="Change-record store. Default: memory (no GitHub HTTP).",
    )
    assess.add_argument(
        "--repository",
        default=None,
        help="owner/repo for --store github (FINDUPDATES_GITHUB_REPOSITORY).",
    )
    assess.add_argument(
        "--dry-run",
        action="store_true",
        help="Write/print records without upserting to GitHub. No token required.",
    )
    assess.add_argument(
        "--skip-enrichment",
        action="store_true",
        help="Skip NVD/CISA KEV lookups. Use for air-gapped or fixture-only runs.",
    )
    assess.add_argument(
        "--skip-notify",
        action="store_true",
        help="Skip severity-aware notifications after each change-record upsert.",
    )
    args = parser.parse_args(argv)
    settings = Settings.from_env()
    configure_logging(settings.log_level)
    output_dir = args.output_dir
    run = assess_collected(
        AssessOptions(
            advisories=args.advisories,
            inventory=args.inventory,
            output_dir=output_dir,
            dry_run=args.dry_run,
            store_name=args.store,
            store=store,
            environ=environ,
            transport=transport,
            repository=args.repository or settings.github_repository,
            skip_enrichment=args.skip_enrichment,
            skip_notify=args.skip_notify,
            settings=settings,
        ),
        now=datetime.now(UTC),
    )
    for note in run.notes:
        print(note)
    if output_dir is not None and run.exit_code == 0:
        print(f"summary={output_dir / 'summary.json'}")
    return run.exit_code


if __name__ == "__main__":
    sys.exit(main())
