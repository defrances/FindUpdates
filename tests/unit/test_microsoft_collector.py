from __future__ import annotations

import datetime
import json
import pathlib
import unittest
import urllib.parse

import jsonschema

import findupdates.collectors.microsoft as microsoft

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "msrc"
SCHEMA_PATH = REPO_ROOT / "schemas" / "update-advisory" / "v1.schema.json"


def _summary() -> microsoft.UpdateSummary:
    return microsoft.UpdateSummary(
        update_id="2026-Sep",
        title="September 2026 Security Updates",
        severity="Critical",
        initial_release_date=datetime.datetime(2026, 9, 8, 17, tzinfo=datetime.UTC),
        current_release_date=datetime.datetime(2026, 9, 10, 17, tzinfo=datetime.UTC),
        cvrf_url=None,
    )


class FakeTransport:
    def __init__(self, responses: dict[str, microsoft.HttpResponse]) -> None:
        self.responses = responses
        self.urls: list[str] = []

    def get(
        self,
        url: str,
        *,
        timeout_seconds: float,
        headers: dict[str, str] | microsoft.Mapping[str, str],
    ) -> microsoft.HttpResponse:
        del timeout_seconds, headers
        self.urls.append(url)
        for marker, response in self.responses.items():
            if marker in url:
                return response
        raise AssertionError(f"unexpected URL: {url}")


class MicrosoftNormalizationTests(unittest.TestCase):
    def _validate_schema(self, advisory: microsoft.UpdateAdvisory) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(
            schema,
            format_checker=jsonschema.FormatChecker(),
        )
        errors = list(validator.iter_errors(advisory.to_dict()))
        self.assertEqual([], errors)

    def test_normalizes_json_cvrf(self) -> None:
        body = (FIXTURE_DIR / "2026-sep.json").read_bytes()
        response = microsoft.HttpResponse(200, "application/json", body, {})

        advisories = microsoft.normalize_cvrf(
            _summary(),
            response,
            collected_at=datetime.datetime(2026, 9, 15, 14, tzinfo=datetime.UTC),
        )

        self.assertEqual(1, len(advisories))
        advisory = advisories[0]
        self.assertEqual(("CVE-2026-9999",), advisory.cve_ids)
        self.assertEqual(("KB5069999",), advisory.kb_ids)
        self.assertTrue(advisory.reboot_required)
        self.assertEqual("win11-24h2-x64", advisory.affected_products[0].product_id)
        self.assertEqual(1, len(advisory.workarounds))
        self._validate_schema(advisory)

    def test_normalizes_xml_when_service_returns_xml(self) -> None:
        body = (FIXTURE_DIR / "2026-sep.xml").read_bytes()
        response = microsoft.HttpResponse(200, "application/xml", body, {})

        advisories = microsoft.normalize_cvrf(
            _summary(),
            response,
            collected_at=datetime.datetime(2026, 9, 15, 14, tzinfo=datetime.UTC),
        )

        self.assertEqual(("CVE-2026-9999",), advisories[0].cve_ids)
        self.assertEqual(("KB5069999",), advisories[0].kb_ids)
        self.assertEqual(
            "Windows 11 Version 24H2 for x64-based Systems",
            advisories[0].affected_products[0].name,
        )
        self._validate_schema(advisories[0])

    def test_rejects_xml_with_doctype(self) -> None:
        response = microsoft.HttpResponse(
            200,
            "application/xml",
            b'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            {},
        )

        with self.assertRaises(microsoft.MsrcParseError):
            microsoft.normalize_cvrf(
                _summary(),
                response,
                collected_at=datetime.datetime(2026, 9, 15, 14, tzinfo=datetime.UTC),
            )


class MicrosoftClientTests(unittest.TestCase):
    def test_incremental_filter_and_collect_metrics_are_deterministic(self) -> None:
        summaries = [
            {
                "ID": "2026-Sep",
                "DocumentTitle": "September 2026 Security Updates",
                "Severity": "Critical",
                "InitialReleaseDate": "2026-09-08T17:00:00Z",
                "CurrentReleaseDate": "2026-09-10T17:00:00Z",
                "CvrfUrl": "https://untrusted.example.invalid/ignored"
            }
        ]
        detail = (FIXTURE_DIR / "2026-sep.json").read_bytes()
        transport = FakeTransport(
            {
                "/Updates?": microsoft.HttpResponse(
                    200,
                    "application/json",
                    json.dumps(summaries).encode(),
                    {},
                ),
                "/cvrf/2026-Sep?": microsoft.HttpResponse(200, "application/json", detail, {}),
            }
        )
        client = microsoft.MsrcClient(transport=transport, sleeper=lambda _: None)
        after = datetime.datetime(2026, 9, 1, tzinfo=datetime.UTC)

        first = client.collect(
            after=after,
            collected_at=datetime.datetime(2026, 9, 15, 14, tzinfo=datetime.UTC),
        )
        known = {item.advisory_id: item.raw_sha256 for item in first.advisories}
        second = client.collect(
            after=after,
            known_hashes=known,
            collected_at=datetime.datetime(2026, 9, 15, 15, tzinfo=datetime.UTC),
        )

        self.assertEqual(1, first.metrics.changed)
        self.assertEqual(0, first.metrics.unchanged)
        self.assertEqual(0, second.metrics.changed)
        self.assertEqual(1, second.metrics.unchanged)
        update_url = next(url for url in transport.urls if "/Updates?" in url)
        parsed_query = urllib.parse.parse_qs(urllib.parse.urlparse(update_url).query)
        self.assertEqual(["CurrentReleaseDate gt 2026-09-01"], parsed_query["$filter"])
        self.assertTrue(all("untrusted.example.invalid" not in url for url in transport.urls))

    def test_one_malformed_document_does_not_discard_valid_document(self) -> None:
        summaries = [
            {
                "ID": "2026-Aug",
                "DocumentTitle": "August 2026 Security Updates",
                "Severity": "Important",
                "InitialReleaseDate": "2026-08-11T17:00:00Z",
                "CurrentReleaseDate": "2026-08-11T17:00:00Z"
            },
            {
                "ID": "2026-Sep",
                "DocumentTitle": "September 2026 Security Updates",
                "Severity": "Critical",
                "InitialReleaseDate": "2026-09-08T17:00:00Z",
                "CurrentReleaseDate": "2026-09-10T17:00:00Z"
            }
        ]
        transport = FakeTransport(
            {
                "/Updates?": microsoft.HttpResponse(
                    200,
                    "application/json",
                    json.dumps(summaries).encode(),
                    {},
                ),
                "/cvrf/2026-Aug?": microsoft.HttpResponse(
                    200,
                    "application/json",
                    b"{not-json",
                    {},
                ),
                "/cvrf/2026-Sep?": microsoft.HttpResponse(
                    200,
                    "application/json",
                    (FIXTURE_DIR / "2026-sep.json").read_bytes(),
                    {},
                ),
            }
        )
        client = microsoft.MsrcClient(transport=transport, sleeper=lambda _: None)

        result = client.collect(
            collected_at=datetime.datetime(2026, 9, 15, 14, tzinfo=datetime.UTC)
        )

        self.assertEqual(1, len(result.advisories))
        self.assertEqual(1, result.metrics.failed)
        self.assertEqual(1, result.metrics.parse_errors)
        self.assertEqual("2026-Aug", result.errors[0].update_id)


if __name__ == "__main__":
    unittest.main()
