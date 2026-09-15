"""CLI: poll Microsoft and Intel collectors. Does not deploy updates."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from findupdates.collectors.runner import PollOptions, poll, resolve_sources, write_summary
from findupdates.config import Settings
from findupdates.logging import configure_logging


def main(argv: list[str] | None = None) -> int:
    """Parse flags and run a collector poll. Exit 1 when a configured source fails."""
    parser = argparse.ArgumentParser(
        prog="python -m findupdates.collectors",
        description=(
            "Poll Microsoft MSRC and Intel CSAF collectors with durable checkpoints. "
            "This command never deploys updates."
        ),
    )
    parser.add_argument(
        "--source",
        action="append",
        dest="sources",
        choices=("msrc", "intel", "all"),
        help="Collector to run. Repeatable. Default: all.",
    )
    parser.add_argument(
        "--checkpoint-dir",
        type=Path,
        default=None,
        help="Directory for checkpoint JSON (FINDUPDATES_CHECKPOINT_DIR).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Optional directory for advisory JSON artifacts and summary.json.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate configuration and planned sources. No vendor HTTP.",
    )
    args = parser.parse_args(argv)
    settings = Settings.from_env()
    configure_logging(settings.log_level)
    try:
        sources = resolve_sources(tuple(args.sources or ("all",)))
    except ValueError as exc:
        parser.error(str(exc))
    checkpoint_dir = args.checkpoint_dir or Path(settings.checkpoint_dir)
    output_dir = args.output_dir
    if output_dir is None and settings.collection_output_dir:
        output_dir = Path(settings.collection_output_dir)
    run = poll(
        PollOptions(
            sources=sources,
            checkpoint_dir=checkpoint_dir,
            output_dir=output_dir,
            dry_run=args.dry_run,
            settings=settings,
        ),
        now=datetime.now(UTC),
    )
    for note in run.notes:
        print(note)
    if output_dir is not None:
        summary = write_summary(run, output_dir)
        print(f"summary={summary}")
    return run.exit_code


if __name__ == "__main__":
    sys.exit(main())
