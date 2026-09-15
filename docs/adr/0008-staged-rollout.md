# ADR-0008: Staged rings with frozen membership and health gates

- Status: Accepted
- Date: 2026-09-15
- Owners: FindUpdates contributors
- Related issues: #5, #27, #29, #30

## Context

An approved `DeploymentRequest` still must not install everywhere at once.
If promotion can proceed without an observation window, without health data,
or onto a widened device list, canary evidence is meaningless.

## Decision

Rollout follows `lab → canary → ring-1 → ring-2 → production`. Membership is
snapshotted and hashed at plan time. Promotion requires observed health, a
completed observation window, and stage-specific thresholds. `INCONCLUSIVE`
critical signals pause the rollout. Clinically critical devices skip early
rings. Canary and later stages honor timezone-aware maintenance windows unless
an authorized emergency process is recorded. Production rings require explicit
environment approval. Partial adapter failure pauses and does not promote.

## Alternatives considered

- Percentage of the whole fleet at production time — membership would drift
  after approval.
- Treating adapter `succeeded` as healthy — ignores post-update crashes and
  connectivity loss.
- Allowing critical devices into canary for speed — concentrates clinical
  risk in the smallest cohort.

## Consequences

### Positive

- Promotion decisions are replayable from `RolloutPlan` plus `RolloutState`.
- Simulated fleets can prove pause, window and approval behavior in CI.

### Negative / risks

- Default percentages are draft policy, not a site-specific clinical schedule.
- Health signals are still caller-supplied; a later monitoring issue must feed
  them from real telemetry.

## Validation

Unit tests cover a full lab-to-production path, threshold pause, incomplete
observation, maintenance windows, emergency override, production approval,
workflow restore, concurrent locks and partial backend failure.

## Revisit triggers

- Live telemetry (#31) replaces simulated health signals.
- Site-specific ring maps replace percentage defaults.
