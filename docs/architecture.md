# Architecture baseline

## Pipeline boundaries

```text
Vendor/intelligence sources
        |
        v
    collectors
        |
        v
   normalization
        |
        +----> enrichment (future)
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
```

## Trust model

External advisory text and vendor payloads are untrusted input. They may influence normalized facts only through validated parsers and may never be treated as executable instructions.

AI output is advisory evidence, not an authorization signal. Applicability, risk score, hard gates, approvals and target scope must remain deterministic and independently auditable.

Deployment credentials are outside the collector/AI processes and should be issued only to approved deployment environments using short-lived identity where possible.

## Data classification

The pipeline needs technical device metadata but does not require patient identifiers or PHI. Synthetic/non-PHI fixtures are mandatory for CI and development.

## Failure behavior

Malformed source data, stale inventory, unknown applicability, missing mandatory validation evidence or missing approval must fail closed for deployment while preserving monitoring/triage capabilities.
