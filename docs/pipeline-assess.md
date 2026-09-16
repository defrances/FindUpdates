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
python -m findupdates.pipeline assess --advisories .findupdates/out --inventory inventory.json --output-dir .findupdates/changes --dry-run --skip-notify
python -m findupdates.pipeline detect --source fixtures --output-dir .findupdates/detect
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

Issue #61 emits a severity-aware notification after each upsert via
`NotificationService.notify_advisory`. The GitHub channel is the in-memory
comment formatter from #25; this command does not POST Issue comments through
the Issues API. An optional webhook is read from
`FINDUPDATES_NOTIFICATION_WEBHOOK_URL` at request time and is never stored on
the change record or in Settings. `--dry-run` maps the webhook slot onto that
in-memory formatter so HIGH+ still emits without HTTP. `--skip-notify` skips
notifications entirely. Unchanged rescans with the same fingerprint are
suppressed in-process. HIGH/CRITICAL/EMERGENCY still require acknowledgement in
the event model; this issue does not add an ack CLI. Notification JSON is
written under `--output-dir/notifications/` when output-dir is set. Delivery
failure is recorded; it does not abort assess or rewrite `policy_result`.

Issue #63 runs bounded agentic analysis after risk unless `--skip-ai` is set.
GitHub Actions `detect.yml` may call Copilot CLI (#83); missing CLI or seat
uses the offline/template provider. Analysis JSON is
written under `--output-dir/analysis/`. AI cannot change `policy_result`.
`python -m findupdates.pipeline detect` stages fixtures or live collector
output, then assess + AI + notify. GitHub Actions `detect.yml` publishes the
markdown report as a Job Summary (the GitHub-side notification) and uploads
artifacts. `collect.yml` stays `--dry-run` and is not a pull-request check.

Issue #67 forms a run-level Agentic AI analysis of the detected updates after
those per-device records exist: `analysis/updates.md` and `analysis/run.json`.
The detect Job Summary opens with that briefing. Change records cite
`analysis:<id>` and reuse Change Planning as `validation_plan`. Notifications
may echo that planning text; they cannot rewrite HOLD/BLOCK.

Issue #69 adds a synthetic non-PHI workstation catalog
(`configs/inventory/synthetic-workstations.json`) and a per-station
recommendation report (`recommendations.md`). The report names which package
is in scope for which station, with a deterministic explanation and an
allow-listed official vendor URL. It does not authorize installation.
GitHub Actions live detect uses that catalog. Issue #81 adds
`SYNTHETIC-W11-24H2-01`, whose OS identity matches a live MSRC Windows 11
24H2 x64 SKU so applicability can return `affected` and the report can list
`candidate_for_validation`. That row still does not authorize installation.
Job Summary leads with the station markdown so the Summary stays under 1 MB.

Issue #71 also writes a self-contained English HTML report
(`recommendations.html`, copied to detect `report.html`). Untrusted titles are
escaped. There is no third-party CSS or JavaScript. Official links remain
allow-listed HTTPS only. The HTML is the operator artifact; Job Summary stays
markdown.

Issue #77 limits live detect collection to the last 45 days of dated vendor
updates. Issue #75 does not copy the monthly CVRF revision onto every CVE;
older CVE years with only catalog stamps are skipped. Issue #79 ignores
MSRC sentinel `ReleaseDate` values and uses `RevisionHistory` when that is
the only usable per-CVE date. Detect artifacts are packed into one archive.
An empty window is not treated as not_affected.

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
- Tokens are not written into advisory, inventory, change-record,
  notification, or analysis JSON. Webhook URLs that embed a credential are not
  logged or written into artifacts.
- NVD API keys are never sent to CISA.
- A missing or failing webhook is a delivery failure, not an assess abort.

## What this issue does not do

Assess does not poll vendors, run lab validation, or invoke a deployment
adapter. It does not post live GitHub Issue comments, persist a cross-process
notification log, or add an acknowledgement CLI. GitHub Actions `collect.yml`
stays `--dry-run` only. `detect.yml` may poll vendors only on schedule or
`workflow_dispatch` with `--source live`; it never deploys. Promotion still uses
`python -m findupdates.changerecords.workflow` and still reads policy from the
stored record.
