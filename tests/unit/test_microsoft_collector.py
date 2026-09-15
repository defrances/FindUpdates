from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from findupdates.collectors.errors import ParseError, SourceUnavailableError
from findupdates.collectors.http import HttpClient, HttpTransportResult, MappingTransport
from findupdates.collectors.microsoft import MicrosoftCollector, cvrf_url, updates_url
from findupdates.normalization import RebootRequirement, TriState, VendorSeverity, advisory_to_dict

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "collectors"
SCHEMA_PATH = REPO_ROOT / "schemas" / "update-advisory" / "v1.schema.json"
MSRC_DOC = cvrf_url("https://api.msrc.microsoft.com/cvrf/v3.0", "2026-Sep")
MSRC_INDEX_HOST = "https://api.msrc.microsoft.com/cvrf/v3.0/Updates"
XML_FIXTURES = REPO_ROOT / "tests" / "fixtures" / "msrc"


def _validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _index_body() -> bytes:
    return json.dumps(
        {
            "value": [
                {
                    "ID": "2026-Sep",
                    "CurrentReleaseDate": "2026-09-09T07:00:00Z",
                    "CvrfUrl": "https://untrusted.example.invalid/ignored",
                }
            ]
        }
    ).encode("utf-8")


class MicrosoftCollectorTests(unittest.TestCase):
    def test_parses_windows_cve_kb_and_build_boundary(self) -> None:
        collector = MicrosoftCollector(
            client=HttpClient(
                transport=MappingTransport({}), max_retries=0, min_interval_seconds=0
            ),
            now=datetime(2026, 9, 15, 12, tzinfo=UTC),
        )
        body = (FIXTURES / "msrc-cvrf-windows.json").read_bytes()

        result = collector.collect_documents([(MSRC_DOC, body)])

        self.assertEqual(result.metrics.collected, 1)
        self.assertEqual(result.metrics.parse_error, 1)
        advisory = result.advisories[0]
        self.assertEqual(advisory.vendor_advisory_id, "CVE-2026-12345")
        self.assertEqual(advisory.cve_ids, ("CVE-2026-12345",))
        self.assertEqual(advisory.package_ids[0].value, "KB5060001")
        self.assertIs(advisory.reboot_requirement, RebootRequirement.REQUIRED)
        self.assertIs(advisory.known_exploited, TriState.FALSE)
        self.assertIs(advisory.vendor_severity, VendorSeverity.HIGH)
        self.assertEqual(advisory.affected_products[0].builds, ("10.0.22621.4037",))
        self.assertEqual([], list(_validator().iter_errors(advisory_to_dict(advisory))))

    def test_advisories_older_than_lookback_are_skipped(self) -> None:
        collector = MicrosoftCollector(
            client=HttpClient(
                transport=MappingTransport({}), max_retries=0, min_interval_seconds=0
            ),
            now=datetime(2026, 9, 30, 12, tzinfo=UTC),
            lookback=timedelta(days=7),
        )
        body = (FIXTURES / "msrc-cvrf-windows.json").read_bytes()
        result = collector.collect_documents([(MSRC_DOC, body)])
        self.assertEqual(result.advisories, ())
        self.assertEqual(result.metrics.collected, 0)
        self.assertGreaterEqual(result.metrics.skipped, 1)

    def test_catalog_stamp_skips_older_cve_year(self) -> None:
        payload = json.loads((FIXTURES / "msrc-cvrf-windows.json").read_text(encoding="utf-8"))
        reprint = json.loads(json.dumps(payload["Vulnerability"][0]))
        reprint["CVE"] = "CVE-2019-0808"
        reprint["Title"] = {"Value": "Win32k Elevation of Privilege Vulnerability"}
        payload["Vulnerability"] = [payload["Vulnerability"][0], reprint]
        collector = MicrosoftCollector(
            client=HttpClient(
                transport=MappingTransport({}), max_retries=0, min_interval_seconds=0
            ),
            now=datetime(2026, 9, 15, 12, tzinfo=UTC),
            lookback=timedelta(days=7),
        )
        result = collector.collect_documents([(MSRC_DOC, json.dumps(payload).encode("utf-8"))])
        ids = {item.cve_ids[0] for item in result.advisories if item.cve_ids}
        self.assertEqual(ids, {"CVE-2026-12345"})
        self.assertEqual(result.metrics.collected, 1)
        self.assertGreaterEqual(result.metrics.skipped, 1)

    def test_per_cve_release_date_keeps_older_cve_in_window(self) -> None:
        payload = json.loads((FIXTURES / "msrc-cvrf-windows.json").read_text(encoding="utf-8"))
        reprint = json.loads(json.dumps(payload["Vulnerability"][0]))
        reprint["CVE"] = "CVE-2019-0808"
        reprint["Title"] = {"Value": "Win32k Elevation of Privilege Vulnerability"}
        reprint["ReleaseDate"] = "2026-09-10T00:00:00Z"
        payload["Vulnerability"] = [reprint]
        collector = MicrosoftCollector(
            client=HttpClient(
                transport=MappingTransport({}), max_retries=0, min_interval_seconds=0
            ),
            now=datetime(2026, 9, 15, 12, tzinfo=UTC),
            lookback=timedelta(days=7),
        )
        result = collector.collect_documents([(MSRC_DOC, json.dumps(payload).encode("utf-8"))])
        self.assertEqual(result.advisories[0].cve_ids, ("CVE-2019-0808",))
        self.assertEqual(result.metrics.collected, 1)

    def test_idempotent_reread_is_unchanged(self) -> None:
        collector = MicrosoftCollector(
            client=HttpClient(
                transport=MappingTransport({}), max_retries=0, min_interval_seconds=0
            ),
            now=datetime(2026, 9, 15, 12, tzinfo=UTC),
        )
        body = (FIXTURES / "msrc-cvrf-windows.json").read_bytes()
        first = collector.collect_documents([(MSRC_DOC, body)])
        second = collector.collect_documents([(MSRC_DOC, body)], checkpoint=first.checkpoint)

        self.assertEqual(first.advisories[0].advisory_id, second.advisories[0].advisory_id)
        self.assertEqual(second.metrics.unchanged, 1)
        self.assertEqual(second.metrics.changed, 0)

    def test_revision_is_changed_and_keeps_identity(self) -> None:
        collector = MicrosoftCollector(
            client=HttpClient(
                transport=MappingTransport({}), max_retries=0, min_interval_seconds=0
            ),
            now=datetime(2026, 9, 15, 12, tzinfo=UTC),
        )
        original = (FIXTURES / "msrc-cvrf-windows.json").read_bytes()
        revised = (FIXTURES / "msrc-cvrf-windows-revised.json").read_bytes()
        first = collector.collect_documents([(MSRC_DOC, original)])
        second = collector.collect_documents([(MSRC_DOC, revised)], checkpoint=first.checkpoint)

        self.assertEqual(first.advisories[0].advisory_id, second.advisories[0].advisory_id)
        self.assertEqual(second.metrics.changed, 1)
        self.assertIs(second.advisories[0].known_exploited, TriState.TRUE)
        self.assertEqual(second.advisories[0].package_ids[0].value, "KB5060999")

    def test_index_collect_and_source_outage(self) -> None:
        now = datetime(2026, 9, 15, 12, tzinfo=UTC)
        body = (FIXTURES / "msrc-cvrf-windows.json").read_bytes()
        transport = _RecordingTransport({MSRC_INDEX_HOST: _index_body(), MSRC_DOC: body})
        healthy = MicrosoftCollector(
            client=HttpClient(
                transport=transport,
                max_retries=0,
                min_interval_seconds=0,
            ),
            now=now,
        )
        result = healthy.collect()
        self.assertEqual(result.metrics.collected, 1)
        self.assertTrue(any("/Updates?" in url for url in transport.urls))
        self.assertTrue(any("api-version=2023-11-01" in url for url in transport.urls))
        self.assertTrue(
            any("%24filter=" in url or "CurrentReleaseDate" in url for url in transport.urls)
        )
        self.assertTrue(all("untrusted.example.invalid" not in url for url in transport.urls))
        self.assertIn(
            "api-version=2023-11-01", updates_url("https://api.msrc.microsoft.com/cvrf/v3.0")
        )

        down = MicrosoftCollector(
            client=HttpClient(
                transport=MappingTransport(
                    {
                        MSRC_INDEX_HOST: _index_body(),
                        MSRC_DOC: HttpTransportResult(status=503, body=b"down"),
                    }
                ),
                max_retries=0,
                min_interval_seconds=0,
            ),
            now=now,
        )
        with self.assertRaises(SourceUnavailableError):
            down.collect()

    def test_xml_document_and_xxe_rejection(self) -> None:
        collector = MicrosoftCollector(
            client=HttpClient(
                transport=MappingTransport({}), max_retries=0, min_interval_seconds=0
            ),
            now=datetime(2026, 9, 15, 12, tzinfo=UTC),
        )
        xml_body = (XML_FIXTURES / "2026-sep.xml").read_bytes()
        result = collector.collect_documents([(MSRC_DOC, xml_body)])
        self.assertEqual(result.metrics.collected, 1)
        self.assertEqual(result.advisories[0].cve_ids, ("CVE-2026-9999",))
        self.assertEqual(result.advisories[0].package_ids[0].value, "KB5069999")
        self.assertIs(result.advisories[0].reboot_requirement, RebootRequirement.REQUIRED)
        self.assertEqual([], list(_validator().iter_errors(advisory_to_dict(result.advisories[0]))))

        blocked = collector.collect_documents(
            [
                (
                    MSRC_DOC,
                    b'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                )
            ]
        )
        self.assertEqual(blocked.metrics.collected, 0)
        self.assertGreaterEqual(blocked.metrics.parse_error, 1)
        self.assertTrue(
            any("DTD" in error or "entity" in error.lower() for error in blocked.errors)
        )
        with self.assertRaises(ParseError):
            from findupdates.collectors.microsoft.xmlcvrf import parse_cvrf_xml

            parse_cvrf_xml(b'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><cvrfdoc/>')


class _RecordingTransport(MappingTransport):
    def __init__(self, responses: dict[str, HttpTransportResult | bytes]) -> None:
        super().__init__(responses)
        self.urls: list[str] = []

    def fetch(self, url: str, headers: dict[str, str], timeout: float) -> HttpTransportResult:
        self.urls.append(url)
        return super().fetch(url, headers, timeout)


if __name__ == "__main__":
    unittest.main()
