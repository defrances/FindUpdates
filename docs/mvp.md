"""MVP demo

Issue #34 wires the implemented pipeline into one repeatable, non-production
demo. CI runs `tests/integration/test_mvp.py` with synthetic fixtures only.

## What is simulated vs not production-ready

Simulated: vendor HTTP (fixtures on disk), Intune/OEM backends
(`MockDeploymentAdapter`), lab devices (`SimulatedTarget`), post-deploy
heartbeats (`simulate_healthy` / failure injectors), GitHub Issues
(`MemoryChangeStore`).

Not production-ready: live collector polling, GitHub Environment reviewers,
signed device agents, WORM evidence archive, hosted dashboards.

## How to reproduce

```bash
python -m pip install -r requirements-dev.lock
set PYTHONPATH=src
python -m unittest tests.integration.test_mvp -v
```

Expected happy path: Microsoft advisory applies to `SYNTHETIC-MED-001`,
Intel advisory is collected but does not match that Windows image, risk
requires approval, offline AI explains without changing policy, a change
record is stored, validation PASSes, canary is approved, staged rollout
reaches `succeeded`, and an evidence bundle verifies.

Safety paths fail closed: not applicable, stale inventory, validation FAIL,
missing approval, widened target set, canary boot failure, missing
telemetry, and duplicate workflow replay.
