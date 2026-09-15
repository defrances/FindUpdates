"""Immutable audit trail

Issue #32 records every pipeline stage as an append-only `EvidenceRecord` chain
and exports a tamper-evident `EvidenceBundle`.

## Provenance

Records are labeled `vendor_fact`, `deterministic`, `ai_interpretation` or
`human_decision`. AI interpretation cannot be marked authoritative. A human
override appends a new approval record; it never rewrites the original
deterministic policy row. Historical parser, policy, prompt and template
versions travel with each record.

## Integrity

Each record binds `content_sha256` of the redacted payload to
`prev_integrity_hash`. The first record links to a genesis digest of 64 zeros.
Exported packages include JSON records, payload attachments and a markdown
narrative. `verify_bundle` walks the chain, attachment digests and the
manifest (including the narrative hash). Altering any of those fails closed.

## Redaction

Secret-like keys and PHI-like strings are replaced with `[REDACTED]` before
the payload is hashed or stored. Credentials must never appear in the evidence
package.

## Reconstruction

A reviewer can explain why a device was or was not updated from the package
alone: source revision, inventory snapshot, applicability, original policy,
approvals, validation, package identity, ring membership, deployment result
and post-deploy health are all present. CI uses synthetic device IDs only.
