# Intel CSAF ingestion

Issue #13 integrates Intel CSAF 2.0 advisories as a machine-readable source. The collector discovers documents from a configured index URL (`FINDUPDATES_INTEL_CSAF_INDEX_URL`) and normalizes each CSAF document into one canonical `UpdateAdvisory`.

## Source contract

The index is operator-configured. Document URLs from the index are fetched only when they are `https` and share the same host as that index. Cross-host, `http`, or credential-bearing URLs are rejected so a poisoned index cannot become an SSRF primitive.

A missing index URL, a malformed index, or failure of every selected document fetch is an outage, not an empty “no updates” catalog. One malformed CSAF document is isolated; other documents continue.

## Normalization boundary

Reboot requirement and known exploitation stay `unknown` unless later enrichment asserts them. The record describes Intel component impact only. It is not authorization to install a generic Intel firmware/BIOS package on a medical device.

This collector does not deploy updates, assign the authoritative project risk score, or call an AI model. Scheduled/CLI polling is documented in `docs/collection-runner.md` (#52).
