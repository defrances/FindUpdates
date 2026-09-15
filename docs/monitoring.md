"""Post-deployment health monitoring

Issue #31 watches each rollout stage after install. Promotion is paused when
health is DEGRADED, FAILED or INCONCLUSIVE. Rollback is never the default.

## Observations

Each device emits `HealthObservation` rows for install, boot, Windows services,
medical application, connectivity, driver/firmware init, resources, clinical
smoke and heartbeat. Stale or missing heartbeats are INCONCLUSIVE, not HEALTHY.

`StageHealthSummary` aggregates those rows, hashes reason codes and projects
counts onto the existing rollout threshold counters.

Observation windows are version-controlled in `configs/monitoring/v1.json` and
are longer for firmware and clinically critical devices.

## Pause vs rollback

Automatic pause is allowed and is the safe default. Automated rollback runs
only when all of these are true:

- the stage overall is FAILED on a rollback-permitted domain (boot or install)
- the adapter advertises `supports_rollback`
- product policy enables rollback for the update kind
- clinically critical members have an explicit rollback authorization

A partial rollback is recorded as `ROLLBACK_PARTIAL` and does not claim
success. Unsupported backends raise instead of reporting `rolled_back`.

## Resume

A paused stage may resume only after a HEALTHY summary with fresh telemetry and
a completed recovery window.

CI uses simulated telemetry and `MockDeploymentAdapter`. No PHI is collected.
