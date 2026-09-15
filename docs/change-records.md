# GitHub change records

Issue #23 uses GitHub Issues and Environments as the control plane after
deterministic risk and optional AI analysis.

## Record

Each advisory plus deployment group maps to one logical change record. The
idempotency key is `stable_id("change", advisory_id, deployment_group)`. Repeated
scans update the same Issue instead of opening duplicates.

The Issue body contains a human summary and a JSON document between

`<!-- findupdates-change-record:v1 -->` markers. `policy_result` in that JSON is
authoritative. The promotion workflow does not accept a policy override input.

## Lifecycle

`detected -> assessed -> validation requested -> validation passed -> awaiting
approval -> canary -> staged rollout -> completed`, with terminal `held` /
`failed` for HOLD/BLOCK.

HOLD and BLOCK cannot be promoted to `canary` or `production` even when a GitHub
Environment reviewer clicks approve. Lab may still run the gate so operators can
inspect evidence.

## Workflow

`.github/workflows/change-promotion.yml` is `workflow_dispatch` only. Pull
requests cannot load production environment secrets. Jobs use `concurrency` per
idempotency key, `permissions` limited to contents/issues/OIDC, and GitHub
Environments `lab`, `canary`, and `production`.

Create those Environments in the repository settings with required reviewers on
`canary` and `production`, and prevent last-pusher self-approval where GitHub
allows it. Deployment credentials belong on the Environment, issued through OIDC,
not as long-lived workflow secrets.

MVP handoff remains simulated/non-production.
