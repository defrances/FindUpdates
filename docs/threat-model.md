# Threat model and trust boundaries

- Status: Accepted for the MVP control plane
- Date: 2026-09-15
- Related issues: #5, #7, #23, #29, #32, #33

## Assets

- Deterministic policy, inventory and applicability decisions
- GitHub Environments and OIDC deployment credentials
- Evidence packages and change-record state
- Operator notification channels

## Threats

| Threat | Boundary | Control |
| --- | --- | --- |
| Poisoned vendor feed / prompt injection | collectors, AI context | Untrusted input, parsers only, AI non-authoritative |
| Compromised GitHub Action | CI / promotion | Pin third-party actions to SHAs; `contents: read` |
| Untrusted pull request | promotion workflow | No `pull_request` trigger; Environment approval |
| Long-lived deploy secrets | adapters | Short-lived OIDC; credentials never on the request |
| Dependency sabotage | lockfiles | `dependency-review` fails on high/critical |
| Credential or PHI in logs | logging, evidence | Redaction before emit/hash |
| Target-set manipulation | adapter | Frozen hash; mismatch rejects |
| Stale catalog treated as empty | collectors | Outage ≠ no updates; freshness alerts |
| Missing telemetry treated as healthy | monitoring / ops | Unobserved is not healthy |
| Deployment during incident | kill switch | `FINDUPDATES_DEPLOYMENTS_ENABLED` / operations config |

## Privileged actions

- Changing `configs/` policy, operations or schemas (CODEOWNERS + review)
- Dispatching change-promotion into `canary` or `production`
- Issuing OIDC tokens (`id-token: write` only on those jobs)
- Engaging the deployment kill switch

## Trust boundaries

Untrusted: vendor advisories, PR code, model output, notification webhooks.

Trusted only after review: committed policy JSON, schemas, pinned Actions.

Never trusted to authorize deploy: AI text, dispatch form `target_environment`, missing telemetry.
