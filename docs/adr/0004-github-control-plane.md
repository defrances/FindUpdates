# ADR-0004: GitHub is the change-control plane

- Status: Accepted
- Date: 2026-09-15
- Owners: FindUpdates contributors
- Related issues: #5, #19, #21, #23

## Context

Assessments must become auditable work items with human approval before any
deployment adapter runs. A GitHub Actions input that can rewrite HOLD/BLOCK into
ALLOW would bypass the risk engine.

## Decision

One GitHub Issue per `(advisory_id, deployment_group)` stores the versioned
change record. Promotion reads `policy_result` from that record. Workflow
dispatch may choose only `lab|canary|production` and an idempotency key.

Production and canary jobs require GitHub Environments. Untrusted pull requests
do not trigger this workflow. Credentials are Environment-scoped OIDC, not
long-lived admin PATs in the workflow file.

## Alternatives considered

- Storing policy on the workflow input — trivial to bypass HOLD/BLOCK.
- Auto-creating production deployments from Actions on `pull_request` — untrusted
  code would sit in front of deploy secrets.
- A custom database as the system of record — duplicates GitHub audit, actors and
  timestamps already required by the epic.

## Consequences

### Positive

- Approvals and overrides are GitHub actors plus timestamps on the Issue and
  Environment.
- Re-scans converge on one Issue.

### Negative / risks

- Environments and reviewer rules must be configured in the GitHub UI; YAML
  alone cannot create them.
- Self-approval prevention is a repository setting, not an in-repo switch.

## Validation

Unit tests cover HIGH-risk record contents, idempotent upsert, BLOCK/HOLD
promotion denial, environment-approval requirement, and the workflow CLI reading
policy only from the JSON file.

## Revisit triggers

- A real (non-simulated) production adapter is introduced after #34.
- GitHub Environment rules cannot express the medical-engineering approval matrix.
