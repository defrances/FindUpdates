# Advisory enrichment

NVD and CISA KEV supply independent vulnerability context after vendor
normalization. They are prioritization signals, not deployment authorization.

## Precedence

- Vendor `affected_products` / product-status remain authoritative.
- NVD CPE data is stored on the enrichment record and is not copied onto inventory matching fields.
- CVSS vectors from NVD are appended with `source` prefixed `nvd:`; vendor CVSS rows are kept.
- A CVE listed in KEV sets `known_exploited=true`. If the vendor asserted `false`, a conflict is recorded.
- Absence from KEV is `kev_listed=false` and must not be treated as proof of no exploitation.

## Failure behavior

If NVD or KEV is unreachable, the last cached record is served and marked stale. Missing cache
plus outage yields `unknown`, never an empty “safe” catalog.
