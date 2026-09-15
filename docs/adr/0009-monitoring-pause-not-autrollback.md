# ADR-0009: Pause rollouts automatically; never assume rollback is safe

- Status: Accepted
- Date: 2026-09-15
- Owners: FindUpdates contributors
- Related issues: #5, #25, #29, #30, #31

## Context

Canary evidence is useless if a boot loop or crash spike still promotes the
next ring. Treating adapter uninstall as the default recovery is also unsafe:
firmware and clinically critical Windows images may not roll back cleanly.

## Decision

Post-deploy monitoring produces `HEALTHY`, `DEGRADED`, `FAILED` or
`INCONCLUSIVE` per device and stage. Missing or stale heartbeat is
`INCONCLUSIVE` and pauses promotion. Automatic pause is permitted. Automatic
rollback is not. Rollback is offered only when adapter capability, product
policy and (for critical devices) an explicit authorization all agree. Pause
and rollback decisions carry machine-readable reason codes and before/after
versions. Operators are notified through the existing operational-failure
channel.

## Alternatives considered

- Auto-rollback on any FAILED canary — may leave a medical workstation on an
  unvalidated previous image.
- Treating missing telemetry as HEALTHY — hides boot loops when the agent dies.
- Coupling health to installer exit codes — already rejected in lab validation.

## Consequences

### Positive

- Subsequent rings stop when canary health degrades.
- Rollback remains an explicit, auditable action.

### Negative / risks

- Simulated telemetry is not a bedside monitor. Live agents are a later issue.
- Policy `rollback_enabled_kinds` must stay reviewed; adding firmware would be
  a new decision.

## Validation

Unit tests cover boot failure, crash spike, connectivity loss, missing/stale
telemetry, unsupported rollback, critical-device authorization, partial
rollback failure, resume-after-healthy and notification emission.

## Revisit triggers

- A signed device agent supplies real heartbeats.
- An OEM firmware channel documents a safe uninstall procedure.
