"""Operations, kill switch and recovery

Issue #33 hardens how the pipeline is run: least privilege, freshness
alerts, an independent deployment kill switch, and crash recovery that
does not reinstall.

## Kill switch

`configs/operations/v1.json` `deployments_enabled` plus environment
`FINDUPDATES_DEPLOYMENTS_ENABLED`. When disabled, `GuardedDeploymentAdapter`
refuses deploy/resume/rollback. Collectors, risk and change records stay up.

## Freshness and alerts

Microsoft, Intel, NVD/KEV and inventory each have a freshness window.
A source that never succeeded, that is older than the window, or that
failed its last fetch is **not healthy** and raises an alert. Missing
pipeline-stage metrics are not healthy.

## Recovery and backup

`DeploymentJournal` records the last adapter result per idempotency key.
After a crash, `recover_or_deploy` returns the journaled result and does
not call the backend again. Evidence packages are backed up with
`backup_evidence` / `restore_evidence` (hash chain verified).

## CI

Third-party Actions are pinned to SHAs. CI and dependency-review use
`contents: read`. Change-promotion is `workflow_dispatch` only. OIDC
(`id-token: write`) is requested only on canary and production jobs.
`fail-on-severity: high` blocks merges with high/critical dependency
findings.

## Emergency disable

1. Set `FINDUPDATES_DEPLOYMENTS_ENABLED=false` in the deployment environment,
   or set `deployments_enabled` to false in operations config via a reviewed
   change.
2. Confirm collectors still record freshness metrics.
3. Re-enable only after the incident review; do not skip validation or
   approval gates.
