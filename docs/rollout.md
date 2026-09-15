# Staged canary and ring rollout

Issue #30 progresses an approved update through `lab → canary → ring-1 →
ring-2 → production` instead of a fleet-wide install.

## Membership

Ring membership is computed when the `RolloutPlan` is created and hashed. A
changed target set requires a new plan. Each device is assigned to one
first-deploy stage. Clinically `high`/`critical` devices skip canary and
ring-1 and only join the production stage.

Lab devices are identified by a `lab` site or a `lab-` deployment group.

## Promotion

A stage may promote only when:

- post-update health signals were observed
- the observation window has elapsed
- failure, crash, connectivity and validation-regression counts are within
  the stage caps
- critical monitoring is not `INCONCLUSIVE`
- the authorized membership hash still matches
- production/ring-2 has explicit environment approval

Install success from the deployment adapter is not a promotion signal. Missing
health data fails closed. A threshold breach pauses the rollout.

## Maintenance windows

Canary and later stages require every member to be inside its timezone-aware
maintenance window. Production rollout outside that window is forbidden unless
an authorized emergency override is recorded on the plan.

## Concurrency and restart

A device cannot belong to two in-progress rollouts. Controller state serializes
to `RolloutState` so a workflow restart can restore locks and continue without
re-installing an idempotent stage. Cancellation stops further promotion;
already completed adapter jobs are not claimed as uninstalled.

CI uses `synthetic_fleet` and `MockDeploymentAdapter`. It does not call a
production MDM.
