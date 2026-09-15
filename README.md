# FindUpdates

FindUpdates is a safety-conscious update intelligence and orchestration project for medical-device environments.

The target pipeline discovers Microsoft and Intel advisories, determines whether they apply to managed devices, calculates deterministic risk/policy outcomes, produces auditable change records, validates updates, and hands approved changes to controlled deployment backends.

## Safety model

- Agentic AI may summarize, correlate and explain evidence, but it is not authoritative for applicability, severity, approval or production deployment.
- Deterministic policy gates are the source of truth for machine-enforceable decisions.
- Unknown or stale applicability data fails safe and must not be interpreted as `not_affected`.
- GitHub is the control plane for code, change records, approvals and evidence; device updates are executed only through approved deployment adapters.
- Production rollout remains gated by a deployment kill switch, least-privilege workflows, freshness alerts and crash recovery that does not reinstall. This repository is not approved for production deployment.
- Patient identifiers and PHI must never enter repository fixtures, logs, model prompts or audit artifacts.

## Repository layout

```text
src/findupdates/          Application packages
  collectors/             Vendor/source ingestion and polling runner
  normalization/          Canonical advisory normalization
  enrichment/             NVD CVSS and CISA KEV context
  inventory/              Device inventory and SBOM handling
  applicability/          Deterministic device/update matching
  risk/                   Risk scoring and policy evaluation
  agents/                 Bounded AI analysis layer
  notifications/          Severity-aware notification adapters
  validation/             Lab validation plans and simulated targets
  deployment/             Approved deployment backend adapters
  rollout/                Staged canary/ring promotion
  monitoring/             Post-deploy health, pause and gated rollback
  audit/                  Evidence and audit trail
  ops/                    Kill switch, metrics, freshness alerts, recovery
  mvp/                    Fixture-driven end-to-end demo runner
configs/                  Version-controlled non-secret configuration
schemas/                  Versioned JSON Schemas
tests/                    Unit, integration and fixtures
docs/                     Architecture and ADRs
.github/                   CI, templates and repository policy
```

## Development

Requires Python 3.12+.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.lock
make check
```

On Windows PowerShell, activate the virtual environment with `.venv\\Scripts\\Activate.ps1`.

## Configuration

Runtime configuration is supplied through environment variables. Copy `.env.example` for local development, but never commit real credentials. Configuration under `configs/` is non-secret policy/environment metadata and should be changed through code review.

## Current roadmap

The engineering backlog is tracked under [EPIC #5](https://github.com/defrances/FindUpdates/issues/5). The repository foundation is implemented under [Issue #7](https://github.com/defrances/FindUpdates/issues/7). The canonical advisory model is [Issue #3](https://github.com/defrances/FindUpdates/issues/3). Microsoft ingestion is [Issue #11](https://github.com/defrances/FindUpdates/issues/11). Intel CSAF ingestion is [Issue #13](https://github.com/defrances/FindUpdates/issues/13). NVD and CISA KEV enrichment is [Issue #15](https://github.com/defrances/FindUpdates/issues/15). Device inventory is [Issue #9](https://github.com/defrances/FindUpdates/issues/9). Applicability matching is [Issue #17](https://github.com/defrances/FindUpdates/issues/17). Deterministic risk and policy evaluation is [Issue #19](https://github.com/defrances/FindUpdates/issues/19). Bounded AI analysis is [Issue #21](https://github.com/defrances/FindUpdates/issues/21). GitHub change records and approval gates are [Issue #23](https://github.com/defrances/FindUpdates/issues/23). Severity-aware notifications are [Issue #25](https://github.com/defrances/FindUpdates/issues/25). Lab validation is [Issue #27](https://github.com/defrances/FindUpdates/issues/27). The deployment adapter boundary is [Issue #29](https://github.com/defrances/FindUpdates/issues/29). Staged canary/ring rollout is [Issue #30](https://github.com/defrances/FindUpdates/issues/30). Post-deployment monitoring is [Issue #31](https://github.com/defrances/FindUpdates/issues/31). The immutable audit trail and evidence package is [Issue #32](https://github.com/defrances/FindUpdates/issues/32). Pipeline security, observability and operational failure handling is [Issue #33](https://github.com/defrances/FindUpdates/issues/33). The MVP end-to-end acceptance demo is [Issue #34](https://github.com/defrances/FindUpdates/issues/34). Live collector polling with durable checkpoints is [Issue #52](https://github.com/defrances/FindUpdates/issues/52). The GitHub Issues change-record adapter is [Issue #54](https://github.com/defrances/FindUpdates/issues/54). Assessing collector output against inventory and upserting those records is [Issue #56](https://github.com/defrances/FindUpdates/issues/56). NVD/CISA KEV enrichment during assess is [Issue #58](https://github.com/defrances/FindUpdates/issues/58). Emitting severity-aware notifications after those upserts is [Issue #61](https://github.com/defrances/FindUpdates/issues/61). Detecting updates, attaching bounded AI analysis, and notifying from GitHub Actions is [Issue #63](https://github.com/defrances/FindUpdates/issues/63).

## Status

Early foundation/MVP development. **Not approved for production medical-device deployment.**
