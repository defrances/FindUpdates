# ADR-0005: Severity-aware notifications are non-authoritative

- Status: Accepted
- Date: 2026-09-15
- Owners: FindUpdates contributors
- Related issues: #5, #19, #23, #25

## Context

Operators need a single actionable message when a HIGH or CRITICAL advisory
hits inventory. Repeating the same assessment on a timer must not page them.
A notification must not be a back-door to rewrite HOLD/BLOCK.

## Decision

Notifications are derived from deterministic risk and the GitHub change record.
Deduplication is a fingerprint of advisory scope, severity, policy, KEV,
device count and lifecycle. Material changes emit a new event that includes the
previous snapshot. Channel adapters are a narrow `send` interface; GitHub and
webhook are the MVP channels.

HIGH/CRITICAL/EMERGENCY require acknowledgement. Unacked CRITICAL/EMERGENCY
escalate. LOW events are rate-limited.

## Alternatives considered

- Email-only with no fingerprint — floods on periodic scans.
- Letting the webhook payload carry a new policy_result — would bypass #19/#23.
- Embedding a Teams SDK in the core package — couples routing to one vendor.

## Consequences

### Positive

- One logical HIGH notification per new assessment, fan-out to configured channels.
- Delivery failures are visible per channel and retried.

### Negative / risks

- Process-local `MemoryNotificationLog` is not multi-instance durable storage.
- Webhook URLs must stay in the secret store, not in committed Settings.

## Validation

Unit tests cover HIGH fan-out, rescan suppression, device-count increase,
operational-failure retries, PHI redaction, escalation and LOW digest batching.

## Revisit triggers

- A durable acknowledgement store is required across processes.
- A production SIEM adapter is introduced.
