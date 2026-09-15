# FindUpdates

FindUpdates is a safety-conscious update intelligence and orchestration project for medical-device environments.

The target pipeline discovers Microsoft and Intel advisories, determines whether they apply to managed devices, calculates deterministic risk/policy outcomes, produces auditable change records, validates updates, and hands approved changes to controlled deployment backends.

## Safety model

- Agentic AI may summarize, correlate and explain evidence, but it is not authoritative for applicability, severity, approval or production deployment.
- Deterministic policy gates are the source of truth for machine-enforceable decisions.
- Unknown or stale applicability data fails safe and must not be interpreted as `not_affected`.
- GitHub is the control plane for code, change records, approvals and evidence; device updates are executed only through approved deployment adapters.
- Production rollout is intentionally out of scope until validation, approval, monitoring and audit controls are implemented.
- Patient identifiers and PHI must never enter repository fixtures, logs, model prompts or audit artifacts.

## Repository layout

```text
src/findupdates/          Application packages
  collectors/             Vendor/source ingestion
  normalization/          Canonical advisory normalization
  enrichment/             NVD CVSS and CISA KEV context
  inventory/              Device inventory and SBOM handling
  applicability/          Deterministic device/update matching
  risk/                   Risk scoring and policy evaluation
  agents/                 Bounded AI analysis layer
  notifications/          Severity-aware notification adapters
  deployment/             Approved deployment backend adapters
  audit/                  Evidence and audit trail
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

The engineering backlog is tracked under [EPIC #5](https://github.com/defrances/FindUpdates/issues/5). The repository foundation is implemented under [Issue #7](https://github.com/defrances/FindUpdates/issues/7). The canonical advisory model is [Issue #3](https://github.com/defrances/FindUpdates/issues/3). Microsoft ingestion is [Issue #11](https://github.com/defrances/FindUpdates/issues/11). Intel CSAF ingestion is [Issue #13](https://github.com/defrances/FindUpdates/issues/13). NVD and CISA KEV enrichment is [Issue #15](https://github.com/defrances/FindUpdates/issues/15). Device inventory is [Issue #9](https://github.com/defrances/FindUpdates/issues/9). Applicability matching is [Issue #17](https://github.com/defrances/FindUpdates/issues/17). Deterministic risk and policy evaluation is [Issue #19](https://github.com/defrances/FindUpdates/issues/19). Bounded AI analysis is [Issue #21](https://github.com/defrances/FindUpdates/issues/21). GitHub change records and approval gates are [Issue #23](https://github.com/defrances/FindUpdates/issues/23).

## Status

Early foundation/MVP development. **Not approved for production medical-device deployment.**
