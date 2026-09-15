# Deployment adapter

Issue #29 puts a backend-neutral boundary between GitHub-controlled approval
and the mechanism that actually installs an update.

## Boundary

GitHub and deterministic policy decide *what* is approved and *when* it may
proceed. The adapter executes only an already-authorized `DeploymentRequest`.
It must not invent devices, broaden a target set, or treat AI output as
authorization.

Microsoft OS/driver channels (`mock-intune`) are separate from OEM firmware
channels (`mock-oem-agent`). Generic Intel firmware is rejected unless the
request is explicitly `oem_qualified`.

## Request

`DeploymentRequest` binds package identity (id, version, SHA-256), an immutable
`approved_target_set_hash`, rollout environment/ring, and evidence: advisory
ids, risk assessment, change-record key, validation result, approver and
approval time. HOLD/BLOCK cannot be represented as authorization. ALLOW_ANALYSIS
is rejected at validate time.

Short-lived OIDC credentials are passed into `deploy`/`pause`/`resume`/
`rollback_or_uninstall`/`cancel`. They are never stored on the request or in
serialized audit records.

## Lifecycle

```text
prepare → validate_request → deploy → status
                                 ├─ pause / resume
                                 ├─ complete (mock helper)
                                 ├─ cancel
                                 └─ rollback_or_uninstall (only if capability is true)
```

`dry_run` validates and records a plan without occupying the install index, so
a later live request can still proceed. The same `idempotency_key`, or a retry
of the same package hash and target set, returns the existing deployment and
does not install again.

## Capabilities and errors

Adapters expose `supports_pause`, `supports_rollback`, supported update kinds
and `auth=oidc`. Unsupported rollback raises `RollbackUnsupported` and must
not be reported as `rolled_back`. Structured errors cover auth, target
mismatch, package mismatch, missing authorization, unqualified firmware,
backend rejection, timeout and partial failure.

CI uses `MockDeploymentAdapter`. It does not call Microsoft Graph, Intune or
OEM management APIs.
