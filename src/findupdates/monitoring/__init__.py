"""Post-deployment health monitoring, automatic pause and gated rollback."""

from findupdates.monitoring.config import load_monitoring_config
from findupdates.monitoring.decide import decide_pause, decide_rollback
from findupdates.monitoring.errors import PromotionBlocked, ResumeDenied, RollbackDenied
from findupdates.monitoring.evaluate import evaluate_stage, to_signals
from findupdates.monitoring.models import (
    SCHEMA_VERSION,
    DecisionAction,
    HealthDomain,
    HealthObservation,
    HealthState,
    MonitoringDecision,
    StageHealthSummary,
)
from findupdates.monitoring.serialize import (
    observation_to_dict,
    summary_to_dict,
)
from findupdates.monitoring.service import PostDeployMonitor
from findupdates.monitoring.simulate import (
    simulate_app_crash_spike,
    simulate_boot_failure,
    simulate_connectivity_loss,
    simulate_healthy,
    simulate_missing_telemetry,
    simulate_stale_heartbeat,
)

__all__ = [
    "SCHEMA_VERSION",
    "DecisionAction",
    "HealthDomain",
    "HealthObservation",
    "HealthState",
    "MonitoringDecision",
    "PostDeployMonitor",
    "PromotionBlocked",
    "ResumeDenied",
    "RollbackDenied",
    "StageHealthSummary",
    "decide_pause",
    "decide_rollback",
    "evaluate_stage",
    "load_monitoring_config",
    "observation_to_dict",
    "simulate_app_crash_spike",
    "simulate_boot_failure",
    "simulate_connectivity_loss",
    "simulate_healthy",
    "simulate_missing_telemetry",
    "simulate_stale_heartbeat",
    "summary_to_dict",
    "to_signals",
]
