# Assess handoff

Issue #56 loads collector output and operator-supplied inventory, then upserts
one change record per `(advisory_id, deployment_group)`. It does not deploy
updates and does not call Intune or OEM backends.

## Run locally

```bash
set PYTHONPATH=src
python -m findupdates.pipeline assess --advisories .findupdates/out --inventory inventory.json --output-dir .findupdates/changes --dry-run
python -m findupdates.pipeline assess --advisories .findupdates/out --inventory inventory.json --output-dir .findupdates/changes --store memory
python -m findupdates.pipeline assess --advisories .findupdates/out --inventory inventory.json --store github --repository owner/repo
python -m findupdates.pipeline assess --advisories .findupdates/out --inventory inventory.json --output-dir .findupdates/changes --skip-enrichment
```

`--advisories` is the collector output directory from #52 (`msrc/*.json`,
`intel/*.json`). `summary.json` is ignored. A single advisory file is also
accepted.

`--inventory` is schema-shaped device JSON, a `{ "devices": [...] }` catalog, or
a JSON array. Empty catalogs fail closed and are never treated as
`not_affected`.

`--dry-run` writes change-record JSON when `--output-dir` is set and performs no
GitHub HTTP. No token is required. `--store github` uses `GitHubChangeStore`
from #54.

Issue #58 applies NVD CVSS and CISA KEV enrichment before applicability and
risk. `--skip-enrichment` skips those lookups (air-gapped or fixture-only).
KEV listing can raise `known_exploited` to true; absence from KEV never forces
false. Vendor `affected_products` are unchanged. Outages keep last-known cache
or stay unknown; they do not abort assess.

## Fail-closed behavior

- Unreadable or malformed advisory JSON exits non-zero and does not upsert.
- Missing, empty, or unreadable inventory exits non-zero.
- Freshness is recomputed at assess time, so a file that claims `fresh` cannot
  stay fresh after its max age.
- Unknown, possibly_affected, and stale inventory still produce a change record
  whose `policy_result` comes from the deterministic engines. HOLD/BLOCK stay
  HOLD/BLOCK.
- An advisory that does not match with strong identity still produces a record.
  Unknown applicability is BLOCK; it is never a silent “no updates” skip.
- Tokens are not written into advisory, inventory, or change-record JSON.
- NVD API keys are never sent to CISA.

## What this issue does not do

Assess does not poll vendors, send notifications, run lab
validation, or invoke a deployment adapter. GitHub Actions `collect.yml` stays
`--dry-run` only. Promotion still uses
`python -m findupdates.changerecords.workflow` and still reads policy from the
stored record.
