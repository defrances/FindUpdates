# UpdateAdvisory schema

Canonical vendor-neutral model for Microsoft, Intel and other advisories. Schema
version `1.0` is embedded in every persisted record.

## Mandatory fields

Every record must include identity, source provenance, timestamps, parser version
and explicit states for severity, reboot, exploitation and completeness. Arrays
may be empty; they must still be present.

Optional *values* use `null` or `unknown`, never omitted keys. Omitted keys are
schema violations.

## Unknown vs negative assertions

`unknown` is a first-class state. Downstream engines must not treat it as
`false`, `not_affected`, `no` reboot, or `none` exploitability.

| Field | Allowed values | Unsafe conversion |
| --- | --- | --- |
| `known_exploited` | `true`, `false`, `unknown` | missing evidence → `false` |
| `reboot_requirement` | `required`, `maybe`, `no`, `unknown` | missing vendor note → `no` |
| `affected_products[].status` | `affected`, `not_affected`, `fixed`, `unknown` | missing mapping → `not_affected` |
| `vendor_severity` | `none` … `critical`, `unknown` | missing rating → `none` |

`known_exploited` is a string tri-state, not a JSON boolean, so schema validation
rejects `false` written as a boolean by accident.

## Identity and merge

1. `vendor` + `vendor_advisory_id` when the vendor ID is present.
2. Else `vendor` + sorted CVE IDs.
3. Else `vendor` + raw source SHA-256.

Revisions of the same logical advisory keep the same `advisory_id`. Merge unions
lists, keeps asserted values over `unknown`, and records a conflict that resets
the field to `unknown` when two asserted values disagree.

## Completeness

`incomplete_fields` lists safety-relevant gaps. Collectors may emit partial
records; applicability and deployment stages must fail closed on those gaps.

## Schema evolution

Additive optional fields may appear in a later `1.x` revision. Removing or
changing the meaning of an existing required field requires a new major schema
directory (`v2`) and an ADR. See [ADR-0001](adr/0001-unknown-states-in-advisory-schema.md).
