# ADR-0006: Lab validation is a hard promotion gate

- Status: Accepted
- Date: 2026-09-15
- Owners: FindUpdates contributors
- Related issues: #5, #9, #23, #27

## Context

A package that installs cleanly can still leave a medical workstation unusable.
If GitHub Environments can be approved without a structured lab report, HOLD and
BLOCK from the risk engine can be bypassed by a human who never saw test
evidence.

## Decision

Each device model has a version-controlled validation profile. Execution produces
a `ValidationResult` with pre/post versions and per-case outcomes. Required
`FAIL`, `BLOCKED` or `INCONCLUSIVE` results block canary and production. The
workflow reads the result file; it has no `validation_passed` input.

`INCONCLUSIVE` required clinical/safety cases are never coerced to `PASS`.
Installation success does not satisfy medical-application cases.

## Alternatives considered

- Treating installer exit code 0 as validation — ignores clinical smoke and
  known issues.
- Allowing reviewers to tick "validated" on the Issue without a result document —
  not replayable.

## Consequences

### Positive

- Promotion evidence is machine-readable and checksummed.
- CI can fail a critical smoke test without hardware.

### Negative / risks

- The default simulator is not a substitute for a physical lab bench.
- Human sign-off for non-automatable cases is still required before promotion.

## Validation

Unit tests cover profile schema, a passing signed-off run, a failing clinical
smoke test that blocks production, and required INCONCLUSIVE known-issue review.

## Revisit triggers

- A hardware-in-the-loop adapter replaces the simulator for a device family.
- Clinical-function tests are formally qualified.
