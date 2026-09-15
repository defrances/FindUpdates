# ADR-0011: Least privilege, kill switch and fail-closed observability

- Status: Accepted
- Date: 2026-09-15
- Owners: FindUpdates contributors
- Related issues: #5, #23, #29, #31, #33

## Context

A working update pipeline is still unsafe if GitHub workflows are
over-privileged, if a stalled vendor feed looks like “no updates”, or if
an incident requires stopping installs while intelligence collection
must continue.

## Decision

Critical workflows declare minimal permissions. Third-party Actions are
pinned to commit SHAs. Change-promotion never runs on pull requests.
OIDC is requested only on canary/production jobs. Deployments can be
disabled independently of collection via operations config or
`FINDUPDATES_DEPLOYMENTS_ENABLED`. Source staleness, collector failure,
deployment failure and missing stage metrics emit alerts and are not
treated as healthy. Interrupted deploys resume from a journal without
reinstalling. High/critical SCA findings block merge.

## Alternatives considered

- Mutable Action tags (`@v4`) — a compromised tag moves under us.
- Promotion on `pull_request` — untrusted code could see Environment
  secrets.
- Treating missing metrics as healthy — hides collector and canary
  outages.
- Coupling kill switch to the whole process — would also stop advisory
  monitoring.

## Consequences

### Positive

- Production credentials stay off PR workflows.
- Operators can halt installs without blinding the catalog.

### Negative / risks

- SHA pins must be updated deliberately.
- In-process metrics are not a hosted dashboard.

## Validation

Unit tests cover kill switch vs collection, freshness alerts, journal
recovery without duplicate install, dead-letter exhaustion, evidence
backup, SCA merge blocking, log redaction and workflow pin/permission
checks.

## Revisit triggers

- A hosted metrics backend is introduced.
- GitHub Environment protection rules are encoded as code.
