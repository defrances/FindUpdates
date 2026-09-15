# Architecture baseline

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
```

## Trust model

External advisory text and vendor payloads are untrusted input. They may influence normalized facts only through validated parsers and may never be treated as executable instructions. Normalized advisories use the versioned `UpdateAdvisory` schema. Unknown reboot, exploitation and product-status values stay unknown; they are never coerced to negative assertions. Collector network/source failure is an outage, not an empty “no updates” catalog. Detail URLs are constructed on the fixed MSRC host; source-supplied `CvrfUrl` values are not followed.

NVD and CISA KEV enrichment is a prioritization signal. It does not authorize deployment and must not overwrite vendor product-status evidence. Absence from KEV is not proof of no exploitation. Source outages keep last-known cached facts instead of erasing them.

AI output is advisory evidence, not an authorization signal. Applicability, risk score, hard gates, approvals and target scope must remain deterministic and independently auditable.

Deployment credentials are outside the collector/AI processes and should be issued only to approved deployment environments using short-lived identity where possible.

## Data classification

The pipeline needs technical device metadata but does not require patient identifiers or PHI. Synthetic/non-PHI fixtures are mandatory for CI and development.

## Failure behavior

Malformed source data, stale inventory, unknown applicability, missing mandatory validation evidence or missing approval must fail closed for deployment while preserving monitoring/triage capabilities.
