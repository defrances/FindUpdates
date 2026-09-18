# Architecture baseline

Illustrated operator-facing pipeline diagrams live in [README.md](../README.md).
This document is the trust-model and fail-closed baseline those diagrams follow.

## Pipeline boundaries

```text
Vendor/intelligence sources
        |
        v
    collectors (MSRC CVRF, Intel CSAF)
        |
        v
   normalization
        |
        +----> enrichment (NVD CVSS + CISA KEV)
        |
        v
 inventory + applicability
        |
        v
 deterministic risk/policy
        |
        +----> bounded AI explanation
        |
        v
 GitHub change/approval workflow
        |
        v
 validation -> deployment adapter -> staged rollout -> monitoring
        |
        v
      audit evidence
        |
        v
   ops (kill switch, alerts)
```

## Trust model

External advisory text and vendor payloads are untrusted input. They may influence normalized facts only through validated parsers and may never be treated as executable instructions. Normalized advisories use the versioned `UpdateAdvisory` schema. Unknown reboot, exploitation and product-status values stay unknown; they are never coerced to negative assertions. Collector network/source failure is an outage, not an empty “no updates” catalog. Detail URLs are constructed on the fixed MSRC host; source-supplied `CvrfUrl` values are not followed. Intel CSAF document URLs are fetched only when they share the https host of the configured index.

NVD and CISA KEV enrichment is a prioritization signal. It does not authorize deployment and must not overwrite vendor product-status evidence. Absence from KEV is not proof of no exploitation. Source outages keep last-known cached facts instead of erasing them.

Unknown, stale or weakly identified inventory must not produce `not_affected`. Strong product identity is required before a negative match.

Risk scoring is a versioned, deterministic function of advisory, inventory, applicability and policy. Hard gates override numeric score. Unknown applicability is `BLOCK`. High CVSS and KEV raise the score and the approval burden; they do not authorize production deployment. Invalid policy fails closed. Draft policy under `configs/policies/` is not production approval.

AI output is advisory evidence, not an authorization signal. Applicability, risk score, hard gates, approvals and target scope must remain deterministic and independently auditable. If a model provider is unavailable, a template still emits the analysis schema and the safety path continues. Vendor advisory text is untrusted data in the model payload and cannot invoke tools.

GitHub Issues store one change record per advisory and deployment group. Promotion workflows read `policy_result` from that record; HOLD/BLOCK cannot be overridden by a dispatch input. Canary and production jobs require GitHub Environments. Pull requests do not run the promotion workflow. `GitHubChangeStore` (#54) upserts that record through the Issues API with a fail-closed transport; CI and the MVP demo keep the in-memory store.

Severity-aware notifications fan out from that change record. Unchanged rescans are suppressed. Material risk, KEV, device-count, policy or operational-failure changes emit a new event. Notifications cannot alter applicability, score or policy.

Lab validation is a version-controlled profile per device model. Required FAIL, BLOCKED or INCONCLUSIVE outcomes block canary and production. Installer success is not a clinical-function pass.

Deployment adapters execute only already-authorized requests. They verify the approved target-set hash and package identity, require short-lived OIDC credentials that are never stored on the request, and refuse unqualified Intel/OEM firmware. Unsupported rollback is an error, not a successful uninstall. Microsoft OS/driver channels are a separate capability set from OEM firmware agents.

Staged rollout proceeds lab → canary → ring-1 → ring-2 → production. Ring membership is hashed at plan time. Promotion requires observed health, a completed observation window and stage thresholds; INCONCLUSIVE critical signals pause. Clinically critical devices skip early rings. Maintenance windows are timezone-aware. Partial adapter failure does not promote.

Post-deployment monitoring classifies each device as HEALTHY, DEGRADED, FAILED or INCONCLUSIVE. Stale or missing heartbeats are not healthy. Automatic pause is allowed; automatic rollback is not. Rollback requires adapter capability, product policy and explicit authorization on clinically critical devices.

The audit trail is an append-only SHA-256 hash chain of `EvidenceRecord` rows from source ingestion through closure. Provenance distinguishes vendor facts, deterministic decisions, AI interpretation and human approvals. AI records cannot be authoritative. Human overrides append new rows; they never rewrite the original automated decision. Exported `EvidenceBundle` packages (JSON + markdown) are tamper-evident. Secrets and PHI are redacted before hashing.

Operational controls sit beside the pipeline: GitHub Actions are least-privilege and SHA-pinned, change-promotion never runs on pull requests, and OIDC is requested only for canary/production. A deployment kill switch stops new installs without stopping collection. Stale or unobserved vendor feeds, collector failures, deployment failures and missing stage metrics raise alerts and are not treated as healthy. Interrupted deploys resume from a journal without duplicate installation.

The MVP demo (`findupdates.mvp.run_mvp`) runs the full lifecycle on synthetic Microsoft and Intel fixtures plus a non-PHI imaging workstation. Mock adapters, simulated lab targets and simulated heartbeats stand in for production backends. The demo is the acceptance test for the epic; it is not a production authorization. Operators can poll vendor feeds with `python -m findupdates.collectors` (#52); that job writes checkpoints and freshness alerts and never deploys. Operators can then assess those advisories against inventory with `python -m findupdates.pipeline assess` (#56), which upserts change records and never deploys. Assess applies NVD/CISA KEV enrichment (#58) before risk unless `--skip-enrichment` is set. After each upsert, assess emits severity-aware notifications (#61) unless `--skip-notify` is set; `--dry-run` does not POST webhooks or upsert GitHub Issues. Bounded agentic analysis (#63) runs after risk unless `--skip-ai` is set; it cannot change policy. After those bound analyses, the pipeline writes a run-level Agentic AI briefing of the detected updates (#67) as `analysis/updates.md`. Issue #69 adds a synthetic workstation catalog and a per-station recommendation report (`recommendations.md`) with allow-listed official vendor URLs; detect Job Summary leads with that markdown so it stays under GitHub's 1 MB limit. Issue #81 adds `SYNTHETIC-W11-24H2-01` with a live MSRC Windows 11 24H2 x64 identity so that station can become a validation candidate. Issue #71 also writes a self-contained English HTML operator report (`recommendations.html` / detect `report.html`) with escaped untrusted text and no third-party scripts. Issue #87 writes the same listed station rows to detect `report.json` and uploads that JSON as a separate Actions artifact; it is not an install authorization. Issue #89 schedules detect once per day (`source=live`) and notifies Orchestrator with the run id so Orchestrator can email results; detect does not create GitHub Issues. Issue #77 limits live collection to the last 45 days of dated vendor updates so one iteration covers a Patch Tuesday plus the prior month without a full historical MSRC dump. Issue #75 does not copy monthly CVRF document revisions onto every CVE and packs detect artifacts into one archive. Issue #79 ignores MSRC sentinel `ReleaseDate` values and uses `RevisionHistory` when that is the only usable per-CVE date. Issue #83 may call GitHub Copilot CLI for a capped number of JSON-only analyses; missing CLI or seat falls back to the offline template, and Copilot cannot use tools or change `policy_result`. GitHub Actions `detect.yml` runs collect/fixtures → assess → station recommendations → Job Summary and never deploys.

Deployment credentials are outside the collector/AI processes and should be issued only to approved deployment environments using short-lived identity where possible.

## Data classification

The pipeline needs technical device metadata but does not require patient identifiers or PHI. Synthetic/non-PHI fixtures are mandatory for CI and development.

## Failure behavior

Malformed source data, stale inventory, unknown applicability, missing mandatory validation evidence or missing approval must fail closed for deployment while preserving monitoring/triage capabilities.
