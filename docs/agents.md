# Bounded AI analysis

Issue #21 adds a reviewer-facing analysis layer after deterministic applicability
and risk. Agents may summarize and explain. They cannot change applicability,
numeric score, policy result, approvals or deployment.

## Contracts

Input is a versioned JSON object with:

- `untrusted_source_text` labeled as vendor DATA, not instructions
- structured `evidence` rows with stable IDs
- an `authoritative` snapshot copied from the matcher and risk engine
- allow-lists for CVE, advisory and device identifiers

Output is `schemas/agent-analysis/v1.schema.json`. Every claim must cite supplied
evidence IDs. Model, prompt and template versions are persisted.

## Agents

Four sections are always present:

- Update Intelligence
- Applicability Review
- Risk Explanation
- Change Planning

There is no tool interface. A provider may only return a JSON object.

## Failure and abuse

- If the model provider is disabled or unavailable, an offline template still
  produces a structured analysis and the pipeline continues.
- Post-validation drops invented CVEs, unknown evidence citations, tool/deploy
  payloads and any attempt to rewrite authoritative fields.
- PHI-like and secret-like strings are redacted before a provider sees them.
- Invalid or empty model output falls back to the template.

The default runtime setting is `FINDUPDATES_AI_ENABLED=false`.

Issue #63 wires this layer into `python -m findupdates.pipeline assess` after
risk (unless `--skip-ai`) and into `python -m findupdates.pipeline detect` for
GitHub Actions. Detect forces the offline provider so Actions need no model
keys. Analysis artifacts never authorize deployment.
