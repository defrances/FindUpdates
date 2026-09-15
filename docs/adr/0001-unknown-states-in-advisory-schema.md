# ADR-0001: Unknown is a first-class advisory state

- Status: Accepted
- Date: 2026-09-15
- Owners: FindUpdates contributors
- Related issues: #3, #5, #11, #13

## Context

Collectors will often lack reboot, exploitation, product-status or severity
facts. If those gaps are stored as JSON `false`, empty arrays interpreted as
"not affected", or omitted keys, later applicability and risk engines can
authorize a skip that was never evidenced.

## Decision

The `UpdateAdvisory` v1 schema stores explicit `unknown` enumerations for
safety-relevant fields. `known_exploited` is a string tri-state rather than a
boolean. Normalization never infers negative assertions. Conflicting asserted
values merge back to `unknown` plus a conflict record.

Schema identity is `schema_version: "1.0"` under `schemas/update-advisory/`.
Breaking changes require a new major schema path.

## Alternatives considered

- Nullable booleans (`true` / `false` / `null`) — `null` is easy to coerce to
  `false` in application code and in JSON Schema consumers.
- Omitting unknown fields — makes "field not collected" indistinguishable from
  "schema evolved and the producer is old".

## Consequences

### Positive

- Schema validation can reject accidental boolean `false` for exploitation.
- Merge/identity logic stays deterministic and auditable.

### Negative / risks

- Producers must populate more required keys, including empty arrays.

## Validation

Unit tests assert fixtures validate, boolean `known_exploited` is rejected, and
missing exploitation remains `unknown` after normalization.

## Revisit triggers

- A later enrichment source provides authoritative exploitation that must be
  represented without losing vendor-source provenance.
- A major schema bump is required for new identifier types.
