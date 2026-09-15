# ADR-0002: Deterministic risk and policy evaluation

- Status: Accepted
- Date: 2026-09-15
- Owners: FindUpdates contributors
- Related issues: #5, #15, #17, #19

## Context

Applicability (#17) and enrichment (#15) produce facts that operators still need
to convert into a machine-enforceable decision. If an LLM, a single CVSS number
or a vendor "critical" label could authorize production work, unknown inventory
and weak matches would be laundered into a deploy path.

## Decision

Risk scoring and policy evaluation are a deterministic function of:

- the normalized advisory
- the device inventory record
- the applicability result
- a versioned policy document

The function returns a 0-100 integer, a severity band, a policy result, reason
codes and a contribution breakdown. Hard gates override the numeric score.
Unknown applicability is `BLOCK`. High CVSS never implies immediate deployment:
the strictest score-derived result in the draft policy is `REQUIRE_APPROVAL`.

Policy is stored as JSON because the runtime lockfile does not include a YAML
parser. Invalid policy fails closed.

## Alternatives considered

- LLM-assisted scoring — not independently auditable and not replayable.
- CVSS-only bands — ignore clinical criticality, exposure, KEV and OEM evidence.
- YAML as the runtime document — would add a parser dependency not present in
  the locked toolchain.

## Consequences

### Positive

- Identical inputs plus policy identity replay to identical JSON.
- Safety-relevant unknowns cannot be outscored into `ALLOW_ANALYSIS`.

### Negative / risks

- Draft weights are not clinically validated; changing them is a reviewed policy
  change, not a silent tuning knob.
- OEM qualification is inferred from verified BIOS/firmware/CPU inventory rows
  until an explicit OEM-attestation field exists.

## Validation

Unit tests cover band golden cases, hard-gate override of high CVSS, byte-stable
serialization, schema validation and rejected invalid policy.

## Revisit triggers

- An explicit OEM qualification field is added to inventory.
- Production policy leaves `draft` status.
- A later issue introduces a distinct "approved for staged rollout" result that
  is still not automatic production deployment.
