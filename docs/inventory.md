# Device inventory and SBOM contract

Issue #9 defines the technical inventory used by the applicability and risk engines. The inventory is deliberately limited to device and software metadata; patient identifiers and PHI are out of scope and must never be collected into this model.

## Source-of-truth principles

- Use stable, non-PHI `device_id` values.
- Prefer directly observed/verified versions over declared CMDB metadata.
- Preserve `unknown` and `unverified` states. Missing data must never be converted into `not_affected`.
- Keep clinical criticality independent from cybersecurity severity.
- Record the inventory source and confidence so downstream decisions can be audited.
- Re-evaluate freshness against the configured maximum age before every applicability/risk assessment.

## Normalized identifiers

Where available, components should carry vendor product identifiers plus CPE and/or PURL identifiers. Free-text names remain useful for humans but are not sufficient evidence for a deterministic `not_affected` decision.

Windows inventory should retain product/edition/version/build/architecture as separate fields. Intel components should retain vendor/product IDs and exact firmware/driver versions where the source can verify them.

## Freshness

`freshness_state` is an evaluated fact, not a permanent property. The record stores `inventory_timestamp`, `freshness_evaluated_at`, and `freshness_max_age_hours` so the result can be reproduced. Stale or unknown inventory must be treated conservatively by later policy logic.

## Candidate inventory sources

Future ingestion adapters may populate the canonical model from Intune/MDM, a signed device-management agent, an approved CMDB, OEM management interfaces, or imported SPDX/CycloneDX SBOM documents. Each adapter must map source-specific fields into the canonical model without inventing missing versions or confidence.

## Schema evolution

The JSON Schema lives under `schemas/device-inventory/<version>.schema.json`. Breaking changes require a new schema version. Readers should reject unsupported major versions rather than silently interpreting them using a newer contract.

## Synthetic example

`configs/device-models/example-windows-intel-device.json` is intentionally synthetic. It demonstrates Windows OS/build data, Intel CPU/chipset/driver inventory, BIOS, a medical application, maintenance window, update-management channel, SBOM reference, confidence, and freshness metadata without containing production device data.
