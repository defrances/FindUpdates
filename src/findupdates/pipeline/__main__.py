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
from findupdates.pipeline.detect import DetectOptions, detect_updates


def main(
    argv: list[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    transport: IssuesTransport | None = None,
    store: ChangeRecordStore | None = None,
) -> int:
    """Assess or detect advisories. Dry-run skips GitHub HTTP. Never deploys."""
    parser = argparse.ArgumentParser(
        prog="python -m findupdates.pipeline",
        description=(
            "Assess collected advisory JSON against inventory, or detect updates "
            "with bounded AI analysis and notifications. This command never deploys."
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
    assess.add_argument(
        "--skip-ai",
        action="store_true",
        help="Skip bounded agentic analysis. Deterministic policy is unchanged.",
    )
    detect = sub.add_parser(
        "detect",
        help="Collect or stage advisories, run bounded AI, and emit notifications",
    )
    detect.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory for advisories, assess artifacts, analysis, notifications, report.md.",
    )
    detect.add_argument(
        "--source",
        choices=("fixtures", "live"),
        default="fixtures",
        help="fixtures: MVP advisories. live: poll MSRC/Intel (no deploy).",
    )
    detect.add_argument(
        "--inventory",
        type=Path,
        default=None,
        help="Inventory JSON. Required for --source live. Fixtures write a matching workstation.",
    )
    detect.add_argument(
        "--enrich",
        action="store_true",
        help="Run NVD/CISA KEV during detect. Default skips enrichment.",
    )
    detect.add_argument(
        "--skip-notify",
        action="store_true",
        help="Skip severity-aware notifications.",
    )
    detect.add_argument(
        "--skip-ai",
        action="store_true",
        help="Skip bounded agentic analysis.",
    )
    args = parser.parse_args(argv)
    settings = Settings.from_env()
    configure_logging(settings.log_level)
    now = datetime.now(UTC)
    if args.command == "detect":
        run = detect_updates(
            DetectOptions(
                output_dir=args.output_dir,
                source=args.source,
                inventory=args.inventory,
                skip_enrichment=not args.enrich,
                skip_notify=args.skip_notify,
                skip_ai=args.skip_ai,
                dry_run=True,
                settings=settings,
            ),
            now=now,
        )
        print(run.report)
        print(f"report={args.output_dir / 'report.md'}")
        return run.exit_code
    output_dir = args.output_dir
    assessed = assess_collected(
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
            skip_ai=args.skip_ai,
            settings=settings,
        ),
        now=now,
    )
    for note in assessed.notes:
        print(note)
    if output_dir is not None and assessed.exit_code == 0:
        print(f"summary={output_dir / 'summary.json'}")
    return assessed.exit_code


if __name__ == "__main__":
    sys.exit(main())
