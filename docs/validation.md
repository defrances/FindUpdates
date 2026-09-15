# Validation lab

Issue #27 runs a version-controlled profile against a representative lab target
before canary or production promotion.

## Profiles

`configs/validation/profiles/` maps a device model and baseline to mandatory and
advisory cases. Domains include boot, OS health, driver/firmware init, medical
application smoke, connectivity, resources, critical services, device I/O,
rollback and vendor known-issue review.

A successful OS/package installation is not treated as a clinical-function pass.
Clinical cases are explicit.

## Outcomes

Each case is `PASS`, `FAIL`, `BLOCKED` or `INCONCLUSIVE`. Required
`INCONCLUSIVE` or `FAIL` cases make `overall` not `PASS` and set
`blocks_promotion`. The GitHub promotion workflow reads that file for canary and
production; it does not accept an outcome override input.

Non-automatable required cases stay `INCONCLUSIVE` until a human sign-off id is
recorded.

## Simulator

CI uses `SimulatedTarget` synthetic workstations. Fixtures contain no patient
data. Pre- and post-update version snapshots and per-case log checksums are
attached as artifacts.
