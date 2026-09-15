"""Collector polling runner.

Issue #52 adds a fail-closed CLI around the Microsoft and Intel collectors
already implemented in #11 and #13. It does not deploy updates and does not
bypass the deployment kill switch — collection stays available when deploys
are disabled.

## Run locally

```bash
set PYTHONPATH=src
python -m findupdates.collectors --dry-run --source all
python -m findupdates.collectors --source msrc --checkpoint-dir .findupdates/checkpoints --output-dir .findupdates/out
```

Environment:

- `FINDUPDATES_MSRC_BASE_URL` / `FINDUPDATES_MSRC_LOOKBACK_DAYS` (default 45)
- `FINDUPDATES_INTEL_CSAF_INDEX_URL` (optional; unset means Intel is skipped)
- `FINDUPDATES_INTEL_LOOKBACK_DAYS` (default 45)
- `FINDUPDATES_CHECKPOINT_DIR` (default `.findupdates/checkpoints`)
- `FINDUPDATES_COLLECTION_OUTPUT_DIR` (optional advisory JSON + `summary.json`)

`--dry-run` prints the planned sources and does not open vendor HTTP sockets.

Issue #77 defaults the lookback to **45 days** so one iteration covers a
Patch Tuesday plus the prior month. MSRC still fetches monthly CVRF documents
in at least that same 45-day document window. Per-CVE `ReleaseDate` /
`RevisionDate` / `RevisionHistory` drive advisory emission. Live MSRC often
sends `ReleaseDate=0001-01-01` with `ReleaseDateSpecified=false`; that
sentinel is missing, not an event (#79). Document-level dates alone are
catalog stamps: CVE years older than the window year are reprints and are
not treated as in-window updates. Sentinel dates before year 2000 are not
treated as in-window updates. An empty window is not `not_affected`. GitHub
Actions packs detect output into one `.tgz` so `upload-artifact` does not
walk tens of thousands of JSON files.

## Fail-closed behavior

- A total fetch failure for a configured source exits non-zero and **does not**
  overwrite the last successful checkpoint. That is an outage, not an empty catalog.
- Unconfigured Intel is an explicit skip (exit 0) with a `source_unobserved`
  freshness alert. It is not treated as a healthy empty Intel feed.
- A stale or failed source emits `source_stale`, `source_unobserved`, or
  `collector_failed`. Loss of telemetry is never a healthy signal.
- Advisory artifacts are technical vendor records. Do not place PHI or production
  credentials in the checkpoint directory.

## What this issue does not do

Polling does not create GitHub change records, run applicability/risk, or talk to
Intune/OEM backends. Use `python -m findupdates.pipeline assess` (#56) to turn
collector JSON plus inventory into change records. `python -m findupdates.pipeline detect`
(#63) can stage fixtures or live collector output, then run bounded AI and
notifications. After that run, #67 writes the Agentic AI analysis of detected
updates (`analysis/updates.md`). The MVP e2e path in #34 remains fixture-driven. GitHub Actions
`collect.yml` runs `--dry-run` only so pull-request CI never depends on live
vendor HTTP. `detect.yml` is schedule/`workflow_dispatch` only (no `pull_request`).
