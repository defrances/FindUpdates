from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlencode

from jsonschema import Draft202012Validator, FormatChecker

from findupdates.collectors.errors import NotFoundError, SourceUnavailableError
from findupdates.collectors.http import HttpClient, HttpTransportResult, MappingTransport
from findupdates.config import Settings
from findupdates.enrichment import (
    DEFAULT_KEV_URL,
    DEFAULT_NVD_URL,
    EnrichmentService,
    KevClient,
    NvdClient,
    enrichment_service_from_settings,
    enrichment_to_dict,
)
from findupdates.normalization import (
    AffectedProduct,
    Architecture,
    NormalizedSourceRecord,
    PackageId,
    PackageKind,
    ProductStatus,
    Provenance,
    TriState,
    UpdateAdvisory,
    Vendor,
    VendorSeverity,
    normalize_source_record,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "enrichment"
SCHEMA_PATH = REPO_ROOT / "schemas" / "enrichment" / "v1.schema.json"
CVE = "CVE-2026-12345"
NVD_URL = f"{DEFAULT_NVD_URL}?{urlencode({'cveId': CVE})}"
NOW = datetime(2026, 9, 15, 12, tzinfo=UTC)


def _advisory(*, exploited: TriState = TriState.UNKNOWN) -> UpdateAdvisory:
    record = NormalizedSourceRecord(
        vendor=Vendor.MICROSOFT,
        source="msrc",
        vendor_advisory_id=CVE,
        title="Windows Kernel Elevation of Privilege Vulnerability",
        published_at=datetime(2026, 9, 8, 17, tzinfo=UTC),
        provenance=Provenance(
            source_url="https://example.invalid/advisory",
            raw_sha256="a" * 64,
            retrieved_at=NOW,
            content_type="application/json",
        ),
        cve_ids=(CVE,),
        package_ids=(PackageId(PackageKind.KB, "KB5060001"),),
        vendor_severity=VendorSeverity.HIGH,
        known_exploited=exploited,
        affected_products=(
            AffectedProduct(
                vendor="microsoft",
                product="Windows 11",
                version_range=None,
                builds=("10.0.22621.4037",),
                architectures=(Architecture.X64,),
                vendor_product_id="11571",
                cpe="cpe:2.3:o:microsoft:windows_11:-:*:*:*:*:*:x64:*",
                status=ProductStatus.AFFECTED,
            ),
        ),
    )
    return normalize_source_record(record)


def _service(responses: dict[str, HttpTransportResult | bytes]) -> EnrichmentService:
    client = HttpClient(
        transport=MappingTransport(responses),
        max_retries=0,
        min_interval_seconds=0,
    )
    return EnrichmentService(
        nvd=NvdClient(client=client),
        kev=KevClient(client=client),
        max_age=timedelta(hours=24),
        now=NOW,
    )


class EnrichmentTests(unittest.TestCase):
    def test_nvd_keeps_multiple_cvss_versions_and_schema(self) -> None:
        service = _service(
            {
                NVD_URL: (FIXTURES / "nvd-cve-2026-12345.json").read_bytes(),
                DEFAULT_KEV_URL: (FIXTURES / "kev-empty.json").read_bytes(),
            }
        )
        outcome = service.enrich(_advisory())
        versions = {item.version.value for item in outcome.records[0].nvd_cvss}
        sources = {item.source for item in outcome.advisory.cvss}

        self.assertEqual(versions, {"3.1", "4.0"})
        self.assertTrue(any(source.startswith("nvd:") for source in sources))
        self.assertIs(outcome.advisory.known_exploited, TriState.UNKNOWN)
        self.assertEqual(len(outcome.advisory.affected_products), 1)
        errors = list(
            Draft202012Validator(
                json.loads(SCHEMA_PATH.read_text(encoding="utf-8")),
                format_checker=FormatChecker(),
            ).iter_errors(enrichment_to_dict(outcome.records[0]))
        )
        self.assertEqual([], errors)

    def test_kev_absence_does_not_prove_not_exploited(self) -> None:
        service = _service(
            {
                NVD_URL: (FIXTURES / "nvd-cve-2026-12345.json").read_bytes(),
                DEFAULT_KEV_URL: (FIXTURES / "kev-empty.json").read_bytes(),
            }
        )
        outcome = service.enrich(_advisory(exploited=TriState.UNKNOWN))
        self.assertIs(outcome.records[0].kev_listed, TriState.FALSE)
        self.assertIs(outcome.advisory.known_exploited, TriState.UNKNOWN)

    def test_kev_listing_overrides_vendor_false_with_conflict(self) -> None:
        service = _service(
            {
                NVD_URL: (FIXTURES / "nvd-cve-2026-12345.json").read_bytes(),
                DEFAULT_KEV_URL: (FIXTURES / "kev-with-cve.json").read_bytes(),
            }
        )
        outcome = service.enrich(_advisory(exploited=TriState.FALSE))
        nvd_cpes = outcome.records[0].nvd_cpes

        self.assertIs(outcome.advisory.known_exploited, TriState.TRUE)
        self.assertTrue(
            any(item.field_path == "known_exploited" for item in outcome.advisory.conflicts)
        )
        self.assertTrue(nvd_cpes)
        self.assertNotIn(nvd_cpes[0], {item.cpe for item in outcome.advisory.affected_products})

    def test_kev_transition_requests_reassessment(self) -> None:
        caches = _service(
            {
                NVD_URL: (FIXTURES / "nvd-cve-2026-12345.json").read_bytes(),
                DEFAULT_KEV_URL: (FIXTURES / "kev-empty.json").read_bytes(),
            }
        )
        first = caches.enrich(_advisory())
        self.assertFalse(
            any(reason.endswith(":entered_kev") for reason in first.reassessment_reasons)
        )

        promoted = EnrichmentService(
            nvd=NvdClient(
                client=HttpClient(
                    transport=MappingTransport(
                        {
                            NVD_URL: (FIXTURES / "nvd-cve-2026-12345.json").read_bytes(),
                            DEFAULT_KEV_URL: (FIXTURES / "kev-with-cve.json").read_bytes(),
                        }
                    ),
                    max_retries=0,
                    min_interval_seconds=0,
                )
            ),
            kev=KevClient(
                client=HttpClient(
                    transport=MappingTransport(
                        {DEFAULT_KEV_URL: (FIXTURES / "kev-with-cve.json").read_bytes()}
                    ),
                    max_retries=0,
                    min_interval_seconds=0,
                )
            ),
            max_age=timedelta(hours=24),
            now=NOW + timedelta(hours=25),
            nvd_cache=caches._nvd_cache,
            kev_cache=caches._kev_cache,
        )
        second = promoted.enrich(_advisory())
        self.assertTrue(second.needs_reassessment)
        self.assertIn(f"{CVE}:entered_kev", second.reassessment_reasons)

    def test_nvd_outage_serves_stale_cache(self) -> None:
        transport = _MutableTransport(
            {
                NVD_URL: (FIXTURES / "nvd-cve-2026-12345.json").read_bytes(),
                DEFAULT_KEV_URL: (FIXTURES / "kev-empty.json").read_bytes(),
            }
        )
        client = HttpClient(transport=transport, max_retries=0, min_interval_seconds=0)
        service = EnrichmentService(
            nvd=NvdClient(client=client),
            kev=KevClient(client=client),
            max_age=timedelta(hours=24),
            now=NOW,
        )
        first = service.enrich(_advisory())
        transport.responses[NVD_URL] = HttpTransportResult(status=503, body=b"down")
        later = EnrichmentService(
            nvd=NvdClient(client=client),
            kev=KevClient(client=client),
            max_age=timedelta(seconds=1),
            now=NOW + timedelta(hours=2),
            nvd_cache=service._nvd_cache,
            kev_cache=service._kev_cache,
        )
        second = later.enrich(_advisory())
        self.assertEqual(first.records[0].nvd_cvss, second.records[0].nvd_cvss)
        self.assertTrue(second.records[0].nvd_stale)
        self.assertGreaterEqual(second.metrics.stale_served, 1)
        self.assertGreaterEqual(second.metrics.source_error, 1)

    def test_fresh_cache_hit_does_not_refetch(self) -> None:
        transport = _CountingTransport(
            {
                NVD_URL: (FIXTURES / "nvd-cve-2026-12345.json").read_bytes(),
                DEFAULT_KEV_URL: (FIXTURES / "kev-empty.json").read_bytes(),
            }
        )
        client = HttpClient(transport=transport, max_retries=0, min_interval_seconds=0)
        service = EnrichmentService(
            nvd=NvdClient(client=client),
            kev=KevClient(client=client),
            max_age=timedelta(hours=24),
            now=NOW,
        )
        service.enrich(_advisory())
        calls_after_first = transport.calls
        service.enrich(_advisory())
        self.assertEqual(transport.calls, calls_after_first)


class EnrichmentFactoryTests(unittest.TestCase):
    def test_nvd_api_key_is_not_sent_to_kev(self) -> None:
        self.assertFalse(hasattr(Settings(), "nvd_api_key"))
        service = enrichment_service_from_settings(Settings(), nvd_api_key="nvd-test-key")
        nvd_headers = service._nvd._client._headers
        kev_headers = service._kev._client._headers
        self.assertEqual(nvd_headers.get("apiKey"), "nvd-test-key")
        self.assertNotIn("apiKey", kev_headers)


class HttpNotFoundTests(unittest.TestCase):
    def test_404_is_not_an_outage(self) -> None:
        client = HttpClient(
            transport=MappingTransport({}),
            max_retries=0,
            min_interval_seconds=0,
        )
        with self.assertRaises(NotFoundError):
            client.get_bytes("https://example.invalid/missing")
        with self.assertRaises(SourceUnavailableError):
            HttpClient(
                transport=MappingTransport(
                    {"https://example.invalid/down": HttpTransportResult(status=503, body=b"x")}
                ),
                max_retries=0,
                min_interval_seconds=0,
            ).get_bytes("https://example.invalid/down")


class _MutableTransport:
    def __init__(self, responses: dict[str, HttpTransportResult | bytes]) -> None:
        self.responses = responses

    def fetch(self, url: str, headers: dict[str, str], timeout: float) -> HttpTransportResult:
        del headers, timeout
        payload = self.responses.get(url)
        if payload is None:
            return HttpTransportResult(status=404, body=b"")
        if isinstance(payload, HttpTransportResult):
            return payload
        return HttpTransportResult(status=200, body=payload)


class _CountingTransport(_MutableTransport):
    def __init__(self, responses: dict[str, HttpTransportResult | bytes]) -> None:
        super().__init__(responses)
        self.calls = 0

    def fetch(self, url: str, headers: dict[str, str], timeout: float) -> HttpTransportResult:
        self.calls += 1
        return super().fetch(url, headers, timeout)


if __name__ == "__main__":
    unittest.main()
