# ADR-0007: Deployment adapters execute only authorized requests

- Status: Accepted
- Date: 2026-09-15
- Owners: FindUpdates contributors
- Related issues: #5, #23, #27, #29

## Context

After a change record is approved and lab validation has passed, something still
has to talk to Windows update management or an OEM firmware channel. If that
client can pick extra devices, swap packages, or treat a model summary as
approval, GitHub gates become decorative.

## Decision

A backend-neutral adapter is the only process allowed to invoke a deployment
mechanism. The control plane supplies a versioned `DeploymentRequest` with an
immutable target-set hash, package identity and evidence links. The adapter
verifies those fields, requires a short-lived OIDC credential that is not
persisted on the request, and refuses HOLD/BLOCK, analysis-only policy, missing
validation, target expansion and package substitution.

Microsoft OS/driver deployment is a different capability set from OEM firmware.
Generic Intel firmware is not installed unless `oem_qualified` is true.
Rollback is invoked only when `supports_rollback` is true; otherwise the
adapter raises and leaves the job unchanged.

Idempotency keys and an install index prevent duplicate submissions from
creating duplicate installations.

## Alternatives considered

- Calling Intune/Graph directly from GitHub Actions — couples secrets to the
  control plane and makes target expansion a workflow-input problem.
- Letting the AI agent invoke deploy tools — contradicts the non-authoritative
  AI boundary.
- Claiming rollback succeeded on backends that cannot uninstall — hides an
  unsafe device state.

## Consequences

### Positive

- Later Microsoft/MDM/OEM adapters can implement the same contract.
- Audit records show who authorized the change and the exact package/targets.
- CI can exercise the full lifecycle with `MockDeploymentAdapter`.

### Negative / risks

- A dishonest `oem_qualified` flag is still a control-plane integrity problem.
- The mock does not prove a production MDM will honor pause or rollback.

## Validation

Unit tests cover an authorized Windows lifecycle, duplicate idempotency keys,
mismatched targets/packages, missing credentials, unqualified firmware, and
explicit unsupported OEM rollback.

## Revisit triggers

- A production Intune or OEM adapter is introduced.
- Staged canary/ring rollout (#30) needs additional adapter operations.
