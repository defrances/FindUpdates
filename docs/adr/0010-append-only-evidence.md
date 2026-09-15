# ADR-0010: Append-only evidence chain

- Status: Accepted
- Date: 2026-09-15
- Owners: FindUpdates contributors
- Related issues: #5, #23, #31, #32

## Context

A medical-device update decision must remain explainable after the fact:
which advisory revision was seen, which inventory snapshot was used, which
policy version scored the device, who approved it, and whether the device
was actually updated. Mutable logs and AI text mixed into the same field as
policy output make that reconstruction unsafe.

## Decision

Evidence is an append-only SHA-256 hash chain of `EvidenceRecord` rows with
explicit provenance. Corrections and human overrides add new records; they
do not overwrite earlier ones. AI output is stored as `ai_interpretation`
and cannot be authoritative. Exported bundles pair machine-readable JSON
with a human narrative; both are covered by a manifest digest so tampering
is detectable. Secrets and PHI are redacted before hashing.

## Alternatives considered

- Mutable database rows with last-write-wins — hides who changed a HOLD to
  ALLOW and when.
- Treating model summaries as the decision record — not independently
  auditable and injectable.
- Hashing only the JSON export and not the markdown narrative — a reviewer
  could be shown a rewritten story that still verifies.

## Consequences

### Positive

- A reviewer can reconstruct a device decision from the package alone.
- Historical policy/parser/prompt versions remain identifiable.

### Negative / risks

- Retention is a config value (`2555` days) and is not yet an operational
  archive job.
- The chain is application-level integrity, not a WORM appliance.

## Validation

Unit tests cover end-to-end export from discovery through closure, detection
of mutated records/attachments/narrative, additive overrides, AI
non-authoritative records, redaction and schema validation.

## Revisit triggers

- A WORM or object-lock archive is introduced.
- Evidence must be signed with an organizational key.
