# Microsoft security-update ingestion

Issue #11 integrates the Microsoft Security Response Center (MSRC) Security Updates API as a machine-readable source. The collector targets the current v3 API contract documented by Microsoft: `https://api.msrc.microsoft.com/cvrf/v3.0` with `api-version=2023-11-01`.

## Source contract

The collector uses `/Updates` to discover monthly security-update documents and `/cvrf/{id}` to fetch details. Incremental discovery uses the API's `CurrentReleaseDate` OData filter. The collector constructs detail URLs on the fixed MSRC host instead of following `CvrfUrl` values from source payloads; this prevents source-controlled URLs from becoming an SSRF primitive.

Microsoft's OpenAPI contract advertises JSON and XML representations. In practice, content negotiation has changed historically, so the parser detects the returned representation and supports both JSON and CVRF 1.1-style XML. Unexpected content types fail closed rather than being interpreted heuristically as a successful empty update set.

## Reliability and safety

- Responses are bounded to 25 MiB.
- HTTP 429 and selected 5xx responses are retried with bounded backoff and `Retry-After` support.
- Transport failures are distinct from a legitimate empty result. If every selected document fetch fails, collection raises instead of returning an empty catalog.
- A malformed detail document is isolated to its update ID; other documents continue processing.
- XML containing DTD/entity declarations is rejected before parsing.
- Every normalized record stores a SHA-256 hash of the raw source payload plus parser version and collection timestamp.
- Re-polling can compare known advisory hashes to produce changed/unchanged metrics.
- Missing fields remain absent/unknown; the collector does not invent applicability or deployment authorization.

## Normalization boundary

A monthly CVRF document is normalized into one `UpdateAdvisory` per vulnerability using the canonical v1 schema (`reboot_requirement`, `known_exploited` and product-status are enumerations with explicit `unknown`). Each record preserves CVE and KB identifiers, affected MSRC product IDs/CPE/builds, source references, revision timestamp and raw payload hash. Missing reboot or exploitation facts stay unknown; they are never stored as boolean `false`.

This collector does not deploy updates, assign the authoritative project risk score, or call an AI model.
