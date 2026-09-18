"""Collector polling runner: checkpoints, freshness alerts and CLI."""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from findupdates.collectors.__main__ import main
from findupdates.collectors.checkpoint import CollectionCheckpoint
from findupdates.collectors.http import HttpTransportResult, MappingTransport
from findupdates.collectors.microsoft import cvrf_url
from findupdates.collectors.persist import load_checkpoint, save_checkpoint
from findupdates.collectors.runner import PollOptions, poll, resolve_sources, write_summary
from findupdates.config import Settings
from findupdates.normalization.serialize import advisory_to_dict
from findupdates.ops.models import AlertCode

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "collectors"
SCHEMA_PATH = REPO_ROOT / "schemas" / "update-advisory" / "v1.schema.json"
MSRC_DOC = cvrf_url("https://api.msrc.microsoft.com/cvrf/v3.0", "2026-Sep")
MSRC_INDEX_HOST = "https://api.msrc.microsoft.com/cvrf/v3.0/Updates"
INTEL_INDEX = "https://example.invalid/csaf/index.json"
INTEL_DOC = "https://example.invalid/csaf/intel-sa-01234.json"
NOW = datetime(2026, 9, 15, 18, tzinfo=UTC)


def _index_body() -> bytes:
    return json.dumps(
        {
            "value": [
                {
                    "ID": "2026-Sep",
                    "CurrentReleaseDate": "2026-09-15T18:00:00Z",
                    "CvrfUrl": "https://untrusted.example.invalid/ignored",
                }
            ]
        }
    ).encode("utf-8")


def _settings(**overrides: object) -> Settings:
    base = Settings(
        http_timeout_seconds=1.0,
        http_max_retries=0,
        http_min_interval_seconds=0.0,
        intel_csaf_index_url=None,
    )
    return replace(base, **overrides)  # type: ignore[arg-type]


def _msrc_transport() -> MappingTransport:
    return MappingTransport(
        {
            MSRC_INDEX_HOST: _index_body(),
            MSRC_DOC: (FIXTURES / "msrc-cvrf-windows.json").read_bytes(),
        }
    )


class CollectorPersistTests(unittest.TestCase):
    def test_checkpoint_round_trip(self) -> None:
        original = CollectionCheckpoint(
            source="msrc",
            watermark="2026-09-15T18:00:00Z",
            document_hashes=(("doc:2026-Sep", "ab" * 32),),
            captured_at=NOW,
        )
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            path = save_checkpoint(directory, original)
            loaded = load_checkpoint(directory, "msrc")
            self.assertTrue(path.exists())
            self.assertEqual(loaded, original)
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                set(payload),
                {"captured_at", "document_hashes", "source", "watermark"},
            )
            self.assertEqual(payload["watermark"], original.watermark)
            self.assertIsNone(load_checkpoint(directory, "intel-csaf"))


class CollectorRunnerTests(unittest.TestCase):
    def test_msrc_poll_writes_checkpoint_and_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            options = PollOptions(
                sources=("msrc",),
                checkpoint_dir=root / "cp",
                output_dir=root / "out",
                settings=_settings(),
                transport=_msrc_transport(),
            )
            first = poll(options, now=NOW)
            self.assertEqual(first.exit_code, 0)
            self.assertEqual(first.sources[0].status, "ok")
            assert first.sources[0].metrics is not None
            self.assertEqual(first.sources[0].metrics.changed, 1)
            checkpoint = load_checkpoint(options.checkpoint_dir, "msrc")
            self.assertIsNotNone(checkpoint)
            advisory_files = list((root / "out" / "msrc").glob("*.json"))
            self.assertEqual(len(advisory_files), 1)
            payload = json.loads(advisory_files[0].read_text(encoding="utf-8"))
            schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
            validator = Draft202012Validator(schema, format_checker=FormatChecker())
            self.assertEqual([], list(validator.iter_errors(payload)))
            assert first.sources[0].result is not None
            self.assertEqual(
                [],
                list(
                    validator.iter_errors(advisory_to_dict(first.sources[0].result.advisories[0]))
                ),
            )
            summary = write_summary(first, root / "out")
            self.assertTrue(summary.exists())

            second = poll(options, now=NOW + timedelta(hours=1))
            assert second.sources[0].metrics is not None
            self.assertEqual(second.sources[0].metrics.unchanged, 1)
            self.assertEqual(second.sources[0].metrics.changed, 0)

    def test_failed_poll_preserves_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkpoint_dir = root / "cp"
            healthy = PollOptions(
                sources=("msrc",),
                checkpoint_dir=checkpoint_dir,
                settings=_settings(),
                transport=_msrc_transport(),
            )
            poll(healthy, now=NOW)
            before = (checkpoint_dir / "msrc.json").read_text(encoding="utf-8")
            failed = PollOptions(
                sources=("msrc",),
                checkpoint_dir=checkpoint_dir,
                settings=_settings(),
                transport=MappingTransport(
                    {MSRC_INDEX_HOST: HttpTransportResult(status=503, body=b"down")}
                ),
            )
            run = poll(failed, now=NOW + timedelta(hours=1))
            self.assertEqual(run.exit_code, 1)
            self.assertEqual(run.sources[0].status, "failed")
            self.assertIn(AlertCode.COLLECTOR_FAILED, {item.code for item in run.alerts})
            self.assertEqual((checkpoint_dir / "msrc.json").read_text(encoding="utf-8"), before)

    def test_unconfigured_intel_is_unobserved_skip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = poll(
                PollOptions(
                    sources=("intel",),
                    checkpoint_dir=Path(tmp),
                    settings=_settings(),
                    transport=MappingTransport({}),
                ),
                now=NOW,
            )
            self.assertEqual(run.exit_code, 0)
            self.assertEqual(run.sources[0].status, "skipped")
            self.assertIsNone(run.sources[0].observation.last_success_at)
            self.assertIn(AlertCode.SOURCE_UNOBSERVED, {item.code for item in run.alerts})
            self.assertFalse((Path(tmp) / "intel-csaf.json").exists())

    def test_configured_intel_polls_index(self) -> None:
        transport = MappingTransport(
            {
                INTEL_INDEX: (FIXTURES / "intel-csaf-index.json").read_bytes(),
                INTEL_DOC: (FIXTURES / "intel-csaf-microcode.json").read_bytes(),
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            run = poll(
                PollOptions(
                    sources=("intel",),
                    checkpoint_dir=Path(tmp),
                    settings=_settings(intel_csaf_index_url=INTEL_INDEX),
                    transport=transport,
                ),
                now=NOW,
            )
            self.assertEqual(run.exit_code, 0)
            self.assertEqual(run.sources[0].status, "ok")
            assert run.sources[0].metrics is not None
            self.assertEqual(run.sources[0].metrics.collected, 1)

    def test_dry_run_does_not_write_checkpoints_or_call_transport(self) -> None:
        class Boom(MappingTransport):
            def fetch(
                self, url: str, headers: dict[str, str], timeout: float
            ) -> HttpTransportResult:
                raise AssertionError(f"dry-run must not fetch {url}")

        with tempfile.TemporaryDirectory() as tmp:
            run = poll(
                PollOptions(
                    sources=("msrc", "intel"),
                    checkpoint_dir=Path(tmp),
                    dry_run=True,
                    settings=_settings(),
                    transport=Boom({}),
                ),
                now=NOW,
            )
            self.assertEqual(run.exit_code, 0)
            self.assertEqual(run.sources[0].status, "dry-run")
            self.assertEqual(run.sources[1].status, "skipped")
            self.assertFalse(any(Path(tmp).iterdir()))

    def test_cli_dry_run_and_unknown_source(self) -> None:
        self.assertEqual(main(["--dry-run", "--source", "all"]), 0)
        with self.assertRaises(SystemExit) as raised:
            main(["--source", "prod"])
        self.assertEqual(raised.exception.code, 2)

    def test_resolve_sources(self) -> None:
        self.assertEqual(resolve_sources(("all",)), ("msrc", "intel"))
        self.assertEqual(resolve_sources(("intel", "msrc", "intel")), ("intel", "msrc"))
        with self.assertRaises(ValueError):
            resolve_sources(("nvd",))


if __name__ == "__main__":
    unittest.main()
