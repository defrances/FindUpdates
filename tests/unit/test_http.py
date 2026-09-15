from __future__ import annotations

import time
import unittest

from findupdates.collectors.errors import SourceUnavailableError
from findupdates.collectors.http import (
    MAX_RESPONSE_BYTES,
    HttpClient,
    HttpTransportResult,
    MappingTransport,
    _read_bounded,
)


class HttpClientTests(unittest.TestCase):
    def test_successful_get_json(self) -> None:
        transport = MappingTransport({"https://example.invalid/item": b'{"ok": true}'})
        client = HttpClient(transport=transport, max_retries=0, min_interval_seconds=0)

        payload = client.get_json("https://example.invalid/item")

        self.assertEqual(payload, {"ok": True})

    def test_retries_then_succeeds(self) -> None:
        transport = _FlakyTransport()
        client = HttpClient(transport=transport, max_retries=2, min_interval_seconds=0)

        payload = client.get_bytes("https://example.invalid/flaky")

        self.assertEqual(payload.body, b"ok")
        self.assertEqual(transport.calls, 3)

    def test_exhausted_retries_are_unavailable(self) -> None:
        transport = MappingTransport(
            {"https://example.invalid/down": HttpTransportResult(status=503, body=b"down")}
        )
        client = HttpClient(transport=transport, max_retries=1, min_interval_seconds=0)

        with self.assertRaises(SourceUnavailableError):
            client.get_bytes("https://example.invalid/down")

    def test_extra_headers_and_min_interval(self) -> None:
        transport = _HeaderTransport(b'{"ok": true}')
        client = HttpClient(
            transport=transport,
            max_retries=0,
            min_interval_seconds=0.2,
            extra_headers={"apiKey": "nvd-test-key"},
        )
        start = time.monotonic()
        client.get_bytes("https://example.invalid/nvd")
        client.get_bytes("https://example.invalid/nvd")
        self.assertGreaterEqual(time.monotonic() - start, 0.15)
        self.assertEqual(transport.headers.get("apiKey"), "nvd-test-key")

    def test_response_exceeds_25_mib_bound(self) -> None:
        with self.assertRaises(SourceUnavailableError):
            _read_bounded(_OversizedStream())
        self.assertEqual(MAX_RESPONSE_BYTES, 25 * 1024 * 1024)


class _OversizedStream:
    def read(self, size: int) -> bytes:
        return b"x" * size


class _FlakyTransport:
    def __init__(self) -> None:
        self.calls = 0

    def fetch(self, url: str, headers: dict[str, str], timeout: float) -> HttpTransportResult:
        del url, headers, timeout
        self.calls += 1
        if self.calls < 3:
            return HttpTransportResult(status=503, body=b"no")
        return HttpTransportResult(status=200, body=b"ok")


class _HeaderTransport:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.headers: dict[str, str] = {}

    def fetch(self, url: str, headers: dict[str, str], timeout: float) -> HttpTransportResult:
        del url, timeout
        self.headers = dict(headers)
        return HttpTransportResult(status=200, body=self.body)


if __name__ == "__main__":
    unittest.main()
