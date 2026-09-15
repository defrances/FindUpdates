"""Operator/GitHub detect pipeline: collect, bounded AI, notify. Does not deploy."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from pathlib import Path

from findupdates.collectors.runner import PollOptions, poll
from findupdates.config import Settings
from findupdates.inventory import (
    catalog_path,
    device_to_dict,
    load_inventory,
    refresh_for_assessment,
)
from findupdates.mvp.fixtures import intel_advisory, microsoft_advisory
from findupdates.normalization.serialize import advisory_to_dict
from findupdates.pipeline.assess import AssessOptions, AssessRun, assess_collected
from findupdates.pipeline.errors import AssessError


@dataclass(frozen=True, slots=True)
class DetectOptions:
    output_dir: Path
    source: str = "fixtures"
    inventory: Path | None = None
    skip_enrichment: bool = True
    skip_notify: bool = False
    skip_ai: bool = False
    dry_run: bool = True
    settings: Settings | None = None


@dataclass
class DetectRun:
    source: str
    assess: AssessRun
    inventory: Path
    advisories: Path
    report: str
    exit_code: int
    notes: list[str] = field(default_factory=list)


def detect_updates(options: DetectOptions, *, now: datetime) -> DetectRun:
    """Collect or stage advisories, then assess with bounded AI and notifications."""
    output = options.output_dir
    output.mkdir(parents=True, exist_ok=True)
    source = options.source.strip().lower()
    notes: list[str] = []
    advisories: Path
    inventory: Path
    if source == "fixtures":
        advisories = _write_fixture_advisories(output / "advisories")
        inventory = options.inventory or _write_fixture_inventory(output, now)
        notes.append("source=fixtures")
    elif source == "live":
        if options.inventory is None:
            raise AssessError("live detect requires --inventory")
        inventory = options.inventory
        advisories = output / "advisories"
        settings = options.settings or Settings.from_env()
        poll_run = poll(
            PollOptions(
                sources=("msrc", "intel"),
                checkpoint_dir=output / "checkpoints",
                output_dir=advisories,
                dry_run=False,
                settings=settings,
            ),
            now=now,
        )
        notes.extend(poll_run.notes)
        if poll_run.exit_code != 0:
            report = _failure_report(source, notes)
            _write_report(output, report)
            return DetectRun(
                source=source,
                assess=AssessRun("", (), poll_run.exit_code, notes),
                inventory=inventory,
                advisories=advisories,
                report=report,
                exit_code=poll_run.exit_code,
                notes=notes,
            )
        notes.append("source=live")
    else:
        raise AssessError(f"unknown detect source {options.source}")
    settings = _offline_ai_settings(options.settings)
    assess = assess_collected(
        AssessOptions(
            advisories=advisories,
            inventory=inventory,
            output_dir=output / "assess",
            dry_run=options.dry_run,
            skip_enrichment=options.skip_enrichment,
            skip_notify=options.skip_notify,
            skip_ai=options.skip_ai,
            settings=settings,
            environ={},
        ),
        now=now,
    )
    notes.extend(assess.notes)
    report = render_detect_report(source, assess, output / "assess")
    _write_report(output, report)
    _copy_html_report(output)
    return DetectRun(
        source=source,
        assess=assess,
        inventory=inventory,
        advisories=advisories,
        report=report,
        exit_code=assess.exit_code,
        notes=notes,
    )


def render_detect_report(source: str, run: AssessRun, assess_dir: Path) -> str:
    """Markdown Job Summary: station recommendations, then compact change counts."""
    lines = [
        "# FindUpdates detect",
        "",
        f"source=`{source}` correlation=`{run.correlation_id}` exit=`{run.exit_code}`",
        "",
        "This job does not deploy updates. Recommendations are not an authorization.",
        "",
    ]
    recs = assess_dir / "recommendations.md"
    if recs.is_file():
        lines.append(recs.read_text(encoding="utf-8").strip())
        lines.append("")
    else:
        lines.extend(
            [
                "## Station update recommendations",
                "",
                "No station recommendation artifacts.",
                "",
            ]
        )
    lines.append("## Changes")
    if not run.changes:
        lines.append("No change records. Empty or failed assess is not treated as not_affected.")
    else:
        policies = Counter(item.policy_result for item in run.changes)
        lines.append(
            f"{len(run.changes)} change records. "
            + ", ".join(f"{name}={count}" for name, count in sorted(policies.items()))
        )
        preview = run.changes[:12]
        for item in preview:
            lines.append(
                f"- `{item.advisory_id}` group=`{item.deployment_group}` "
                f"verdicts={','.join(item.verdicts)} policy=`{item.policy_result}` "
                f"score={item.risk_score}"
            )
        extra = len(run.changes) - len(preview)
        if extra:
            lines.append(f"- … {extra} more change records in summary.json")
    lines.extend(["", "## Artifacts"])
    lines.append(
        "Operator HTML report is `report.html` (English, self-contained). "
        "GitHub Job Summary stays markdown so it remains under 1 MB."
    )
    lines.append("Full bounded AI briefing is `assess/analysis/updates.md` in the job artifact.")
    lines.append("")
    return "\n".join(lines)


def _write_fixture_advisories(output: Path) -> Path:
    for vendor, advisory in (("msrc", microsoft_advisory()), ("intel", intel_advisory())):
        folder = output / vendor
        folder.mkdir(parents=True, exist_ok=True)
        payload = advisory_to_dict(advisory)
        path = folder / f"{payload['advisory_id']}.json"
        path.write_text(
            json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return output


def _write_fixture_inventory(output: Path, now: datetime) -> Path:
    path = output / "inventory.json"
    devices = tuple(
        refresh_for_assessment(
            replace(item, inventory_timestamp=now - timedelta(hours=2)),
            now,
        )
        for item in load_inventory(catalog_path())
    )
    payload = {
        "schema_version": "1.0",
        "devices": [device_to_dict(item) for item in devices],
    }
    path.write_text(
        json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _offline_ai_settings(settings: Settings | None) -> Settings:
    base = settings or Settings.from_env()
    return replace(base, ai_enabled=True, ai_provider="offline")


def _write_report(output: Path, report: str) -> None:
    (output / "report.md").write_text(report, encoding="utf-8")


def _copy_html_report(output: Path) -> None:
    source = output / "assess" / "recommendations.html"
    if source.is_file():
        (output / "report.html").write_text(source.read_text(encoding="utf-8"), encoding="utf-8")


def _failure_report(source: str, notes: list[str]) -> str:
    body = "\n".join(f"- {note}" for note in notes) or "- (no notes)"
    return (
        "# FindUpdates detect\n\n"
        f"source=`{source}` exit=`1`\n\n"
        "Collection failed closed. This is not a healthy empty catalog.\n\n"
        f"{body}\n"
    )
