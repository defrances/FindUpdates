"""Export a human-readable plus machine-readable evidence package."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from findupdates.audit.hashing import manifest_digest
from findupdates.audit.models import EvidenceAttachment, EvidenceBundle
from findupdates.audit.serialize import bundle_to_dict, dict_to_record, record_to_dict
from findupdates.audit.store import EvidenceStore
from findupdates.audit.verify import verify_bundle, verify_chain
from findupdates.ids import stable_id

_CONFIG = Path(__file__).resolve().parents[3] / "configs" / "audit" / "v1.json"


def load_audit_config(path: Path | None = None) -> dict[str, Any]:
    payload = json.loads((path or _CONFIG).read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("version") != "1.0":
        raise ValueError("unsupported audit config version")
    return {str(key): value for key, value in payload.items()}


def load_retention_days(path: Path | None = None) -> int:
    return int(load_audit_config(path)["retention_days"])


def export_bundle(
    store: EvidenceStore,
    correlation_id: str,
    *,
    now: datetime,
    narrative: str,
    retention_days: int | None = None,
) -> EvidenceBundle:
    """Snapshot the append-only log. The log itself is not rewritten."""
    records = store.records(correlation_id)
    attachments = store.attachments(correlation_id)
    tip = verify_chain(records)
    days = retention_days if retention_days is not None else load_retention_days()
    bundle_id = stable_id("ev-bundle", correlation_id, now.isoformat())
    bundle = EvidenceBundle(
        bundle_id=bundle_id,
        correlation_id=correlation_id,
        created_at=now,
        retention_days=days,
        chain_tip=tip,
        manifest_sha256=manifest_digest(
            bundle_id=bundle_id,
            chain_tip=tip,
            records=records,
            attachments=attachments,
            narrative=narrative,
        ),
        records=records,
        attachments=attachments,
        narrative=narrative,
    )
    verify_bundle(bundle)
    return bundle


def write_package(bundle: EvidenceBundle, directory: Path) -> None:
    """Write JSON + markdown + attachments. Existing files are not overwritten."""
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / "bundle.json"
    md_path = directory / "README.md"
    if json_path.exists() or md_path.exists():
        raise FileExistsError("refusing to overwrite an exported evidence package")
    json_path.write_text(
        json.dumps(bundle_to_dict(bundle), ensure_ascii=True, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    md_path.write_text(bundle.narrative, encoding="utf-8")
    records_dir = directory / "records"
    attachments_dir = directory / "attachments"
    records_dir.mkdir()
    attachments_dir.mkdir()
    for item in bundle.records:
        path = records_dir / f"{item.sequence:02d}-{item.stage.value}.json"
        path.write_text(
            json.dumps(record_to_dict(item), ensure_ascii=True, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    for attachment in bundle.attachments:
        path = attachments_dir / attachment.name
        if path.exists():
            raise FileExistsError(f"refusing to overwrite {path}")
        path.write_text(attachment.body, encoding="utf-8")


def load_package(directory: Path) -> EvidenceBundle:
    """Rebuild a bundle from an exported directory, including attachment bodies."""
    payload = json.loads((directory / "bundle.json").read_text(encoding="utf-8"))
    narrative = (directory / "README.md").read_text(encoding="utf-8")
    records = tuple(dict_to_record(item) for item in payload["records"])
    attachments = []
    for item in payload["attachments"]:
        name = str(item["name"])
        body = (directory / "attachments" / name).read_text(encoding="utf-8")
        attachments.append(
            EvidenceAttachment(
                name=name,
                sha256=str(item["sha256"]),
                media_type=str(item["media_type"]),
                body=body,
            )
        )
    return EvidenceBundle(
        bundle_id=str(payload["bundle_id"]),
        correlation_id=str(payload["correlation_id"]),
        created_at=_parse_created(str(payload["created_at"])),
        retention_days=int(payload["retention_days"]),
        chain_tip=str(payload["chain_tip"]),
        manifest_sha256=str(payload["manifest_sha256"]),
        records=records,
        attachments=tuple(attachments),
        narrative=narrative,
        schema_version=str(payload.get("schema_version", "1.0")),
    )


def payloads_by_stage(bundle: EvidenceBundle) -> list[tuple[str, str, dict[str, Any], bool]]:
    """Return (stage, provenance, payload, authoritative) from the package alone."""
    rows: list[tuple[str, str, dict[str, Any], bool]] = []
    for record, attachment in zip(bundle.records, bundle.attachments, strict=True):
        parsed = json.loads(attachment.body)
        if not isinstance(parsed, dict):
            raise ValueError(f"attachment {attachment.name} is not an object")
        rows.append((record.stage.value, record.provenance.value, parsed, record.authoritative))
    return rows


def _parse_created(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("created_at must be timezone-aware")
    return parsed
