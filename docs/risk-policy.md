# Risk scoring and policy evaluation

Issue #19 turns applicability, enrichment and inventory facts into a deterministic
risk assessment. The engine does not call an LLM and cannot be overridden by
free-text inference.

## Outputs

Each advisory-device pair receives:

- an integer score in `0..100`
- a severity band: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `EMERGENCY`
- a policy result: `ALLOW_ANALYSIS`, `REQUIRE_VALIDATION`, `REQUIRE_APPROVAL`,
  `HOLD`, or `BLOCK`
- reason codes, weighted score contributions, applied hard gates and the policy
  version

Identical inputs and the same policy identity produce identical JSON.

## Hard gates

Numeric score never authorizes a weaker outcome than an independent gate:

- unknown applicability → `BLOCK`
- `possibly_affected` → `HOLD`
- stale inventory → `HOLD`
- unknown clinical criticality or network exposure → `HOLD`
- firmware/BIOS/microcode on a high/critical clinical device without verified OEM
  hardware evidence → `HOLD`
- affected with low or unknown confidence → `HOLD`

`not_affected` stays `ALLOW_ANALYSIS` so a high CVSS on an unmatched product does
not create a deployment-shaped result.

## Score bands

Draft policy `configs/policies/v1.json` maps bands to operator work, not to
automatic production deployment. `HIGH`, `CRITICAL` and `EMERGENCY` all require
human approval. There is no policy result that means "deploy now".

Weights include vendor severity, CVSS, clinical criticality and network exposure.
Modifiers include KEV, high exploitability, network/no-auth CVSS, reboot,
firmware/BIOS, known issues and missing workaround. Missing CVSS is recorded; it
is not treated as proof of low risk.

## Policy documents

The engine loads JSON. The YAML file under `configs/policies/` is the
operator-facing copy of the same draft ruleset. Invalid policy fails closed.
Draft status is not production approval.
