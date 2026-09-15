# ADR-0003: AI is non-authoritative and removable

- Status: Accepted
- Date: 2026-09-15
- Owners: FindUpdates contributors
- Related issues: #5, #17, #19, #21

## Context

Operators need concise explanations of advisories, applicability and risk. If a
model can change those facts, approve work, or invoke deployment, prompt
injection through vendor text becomes a safety incident.

## Decision

The agent layer consumes structured pipeline records plus bounded, redacted
source excerpts. It emits a versioned `AgentAnalysis` document. Authoritative
applicability, score and policy are copied from the deterministic engines after
the model returns. Providers expose a single `complete` method; there are no
deploy or approve tools.

When a provider is unavailable, a deterministic template still produces the
analysis schema so change-planning records can exist without AI.

## Alternatives considered

- Letting the model return the policy result — not auditable and injectable.
- Skipping analysis when AI is down — would block triage records on an optional
  component.
- Shipping an HTTP model SDK in the lockfile — not required for the bounded
  contract and would pull unused network surface into CI.

## Consequences

### Positive

- AI can be disabled without stopping scoring or applicability.
- Injection and invented identifiers fail closed to human review.

### Negative / risks

- Offline templates are not a substitute for a reviewed production model.
- Redaction is pattern-based and must be expanded if new PHI fields appear.

## Validation

Unit tests cover Microsoft and Intel representative advisories, provider outage
fallback, vendor-text injection, tool/deploy payloads, invented CVEs and PHI
redaction.

## Revisit triggers

- A production model provider is added behind secret-store credentials.
- An explicit OEM or PHI field is introduced on inventory.
