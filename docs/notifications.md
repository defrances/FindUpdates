# Severity-aware notifications

Issue #25 notifies engineers and operators after a change record exists. Routing
is policy, not free-text inference. Payloads are technical identifiers only.

## Event

`NotificationEvent` includes advisory/CVE/KB/vendor IDs, risk score and band,
device count and groups/models, reason codes, applicability confidence and
unknowns, recommended next action, workflow state, a link to the GitHub change
record, and whether acknowledgement is required.

Identical fingerprints are suppressed so an unchanged rescan does not send again.
A new event is emitted when severity increases, KEV appears, affected-device
count increases, policy changes, or validation/deployment fails.

## Channels

Adapters implement a single `send` method. MVP ships GitHub comment formatting
and an HTTPS webhook POST. Teams, Slack and SIEM can be added as additional
adapters without changing the dispatcher.

Draft routing is `configs/notifications/v1.json`. HIGH/CRITICAL/EMERGENCY require
acknowledgement. CRITICAL/EMERGENCY escalate if still unacked after the configured
window. LOW events are rate-limited and then batched into a digest.

## Safety

Delivery logs record channel, event id and success/failure only. Patient
identifiers are redacted before the payload is built. Notifications never change
applicability, score or policy.
