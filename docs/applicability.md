# Applicability engine

Issue #17 determines which managed devices are affected by a normalized advisory.
The decision is deterministic: it does not call an LLM and cannot be overridden by
free-text inference.

## Verdicts

Each advisory-device pair is classified as `affected`, `not_affected`,
`possibly_affected`, or `unknown`. Confidence is independent from vendor severity.

`unknown` and low-confidence `possibly_affected` block automatic production
deployment. Stale or unverified inventory can still yield `affected` when the
product identity matches, but it must never be converted into `not_affected`.

## Matching

- Windows: product identifiers, CPE, edition/family name, architecture, and
  build/UBR ranges (including `10.0.build.ubr` vs `build.ubr` inventory forms).
- Intel: CPU, chipset, BIOS/firmware and driver rows using vendor product IDs,
  CPE and version ranges.
- SBOM: CPE/PURL identifiers on software components. A PURL match is treated as
  strong identity; a name-only match is `possibly_affected`.

Vendor `not_affected` is honored only when a strong identifier matched. Empty
`affected_products` is `unknown`, not `not_affected`.

## Reassessment

The input fingerprint covers advisory identity/revision/hash plus device id,
inventory timestamp and freshness. Bulk evaluation sorts by `advisory_id` then
`device_id` so identical inputs replay in the same order.
