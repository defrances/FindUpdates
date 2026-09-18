"""Durable collector checkpoints. A failed poll must not overwrite the last success."""

from __future__ import annotations

import json
from pathlib import Path

from findupdates.collectors.checkpoint import CollectionCheckpoint
from findupdates.collectors.errors import ParseError
from findupdates.collectors.jsonutil import parse_datetime

_ALLOWED = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")


def checkpoint_path(directory: Path, source: str) -> Path:
    """Return the JSON path for one vendor source."""
    safe = "".join(char if char in _ALLOWED else "-" for char in source.strip().lower())
    if not safe.strip("-"):
        raise ValueError("checkpoint source must not be empty")
    return directory / f"{safe}.json"


def load_checkpoint(directory: Path, source: str) -> CollectionCheckpoint | None:
    """Load a checkpoint or None when the file is absent."""
    path = checkpoint_path(directory, source)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ParseError(f"checkpoint {path} is unreadable") from exc
    if not isinstance(payload, dict):
        raise ParseError(f"checkpoint {path} must be a JSON object")
    raw_source = payload.get("source")
    watermark = payload.get("watermark")
    captured = parse_datetime(payload.get("captured_at"))
    hashes = payload.get("document_hashes")
    if not isinstance(raw_source, str) or not raw_source.strip():
        raise ParseError(f"checkpoint {path} is missing source")
    if captured is None:
        raise ParseError(f"checkpoint {path} is missing captured_at")
    if watermark is not None and not isinstance(watermark, str):
        raise ParseError(f"checkpoint {path} watermark must be a string")
    if not isinstance(hashes, list):
        raise ParseError(f"checkpoint {path} document_hashes must be an array")
    pairs: list[tuple[str, str]] = []
    for item in hashes:
        if (
            not isinstance(item, list)
            or len(item) != 2
            or not isinstance(item[0], str)
            or not isinstance(item[1], str)
        ):
            raise ParseError(f"checkpoint {path} has an invalid document hash entry")
        pairs.append((item[0], item[1]))
    return CollectionCheckpoint(
        source=raw_source.strip(),
        watermark=watermark,
        document_hashes=tuple(pairs),
        captured_at=captured,
    )


def save_checkpoint(directory: Path, checkpoint: CollectionCheckpoint) -> Path:
    """Atomically replace the checkpoint file after a successful collect."""
    directory.mkdir(parents=True, exist_ok=True)
    path = checkpoint_path(directory, checkpoint.source)
    payload = {
        "source": checkpoint.source,
        "watermark": checkpoint.watermark,
        "document_hashes": [list(item) for item in checkpoint.document_hashes],
        "captured_at": checkpoint.captured_at.isoformat().replace("+00:00", "Z"),
    }
    encoded = json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(encoded, encoding="utf-8")
    tmp.replace(path)
    return path
