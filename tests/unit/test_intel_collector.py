from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from findupdates.collectors.errors import SourceUnavailableError
from findupdates.collectors.http import HttpClient, MappingTransport
from findupdates.collectors.intel import IntelCollector
from findupdates.normalization import ProductStatus, RebootRequirement, TriState, advisory_to_dict

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "collectors"
SCHEMA_PATH = REPO_ROOT / "schemas" / "update-advisory" / "v1.schema.json"
INDEX_URL = "https://example.invalid/csaf/index.json"
DOC_URL = "https://example.invalid/csaf/intel-sa-01234.json"


def _validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


class IntelCollectorTests(unittest.TestCase):
    def test_parses_csaf_component_impact_without_inventing_reboot(self) -> None:
        collector = IntelCollector(
            client=HttpClient(
                transport=MappingTransport({}), max_retries=0, min_interval_seconds=0
            ),
            index_url=INDEX_URL,
            now=datetime(2026, 9, 15, 12, tzinfo=UTC),
        )
        body = (FIXTURES / "intel-csaf-microcode.json").read_bytes()

        result = collector.collect_documents([(DOC_URL, body)])

        self.assertEqual(result.metrics.collected, 1)
        advisory = result.advisories[0]
        self.assertEqual(advisory.vendor_advisory_id, "INTEL-SA-01234")
        self.assertEqual(advisory.cve_ids, ("CVE-2026-22222",))
        self.assertIs(advisory.affected_products[0].status, ProductStatus.AFFECTED)
        self.assertIs(advisory.reboot_requirement, RebootRequirement.UNKNOWN)
        self.assertIs(advisory.known_exploited, TriState.UNKNOWN)
        self.assertIsNone(advisory.vendor_recommendation)
        self.assertEqual([], list(_validator().iter_errors(advisory_to_dict(advisory))))

    def test_malformed_document_is_isolated(self) -> None:
        collector = IntelCollector(
            client=HttpClient(
                transport=MappingTransport({}), max_retries=0, min_interval_seconds=0
            ),
            index_url=INDEX_URL,
            now=datetime(2026, 9, 15, 12, tzinfo=UTC),
        )
        good = (FIXTURES / "intel-csaf-microcode.json").read_bytes()
        bad = b'{"document": {"title": "missing tracking"}}'

        result = collector.collect_documents(
            [(DOC_URL, good), ("https://example.invalid/csaf/bad.json", bad)]
        )

        self.assertEqual(result.metrics.collected, 1)
        self.assertEqual(result.metrics.parse_error, 1)

    def test_index_collect_and_missing_index_config(self) -> None:
        now = datetime(2026, 9, 15, 12, tzinfo=UTC)
        transport = MappingTransport(
            {
                INDEX_URL: (FIXTURES / "intel-csaf-index.json").read_bytes(),
                DOC_URL: (FIXTURES / "intel-csaf-microcode.json").read_bytes(),
            }
        )
        collector = IntelCollector(
            client=HttpClient(transport=transport, max_retries=0, min_interval_seconds=0),
            index_url=INDEX_URL,
            now=now,
        )
        result = collector.collect()
        self.assertEqual(result.metrics.collected, 1)

        unconfigured = IntelCollector(
            client=HttpClient(
                transport=MappingTransport({}), max_retries=0, min_interval_seconds=0
            ),
            index_url=None,
            now=now,
        )
        with self.assertRaises(SourceUnavailableError):
            unconfigured.collect()


if __name__ == "__main__":
    unittest.main()
