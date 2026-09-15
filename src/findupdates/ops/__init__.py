"""Pipeline security, observability, kill switch and failure recovery."""

from findupdates.ops.alerts import AlertBus, alert_deployment_failed, alert_for_freshness
from findupdates.ops.backup import backup_evidence, restore_evidence
from findupdates.ops.config import deployments_enabled, load_operations_config
from findupdates.ops.deadletter import DeadLetterQueue
from findupdates.ops.errors import (
    DeadLetterExhausted,
    DeploymentDisabled,
    IntegrityMismatch,
    OpsError,
)
from findupdates.ops.freshness import evaluate_freshness
from findupdates.ops.guard import GuardedDeploymentAdapter
from findupdates.ops.integrity import verify_digest, verify_file, verify_package
from findupdates.ops.killswitch import assert_deployments_enabled
from findupdates.ops.metrics import PipelineMetrics
from findupdates.ops.models import (
    SCHEMA_VERSION,
    Alert,
    AlertCode,
    FreshnessState,
    MetricSample,
    PipelineStage,
    ScannerFinding,
    SourceObservation,
)
from findupdates.ops.recovery import DeploymentJournal, recover_or_deploy
from findupdates.ops.scanner import merge_allowed
from findupdates.ops.secrets import scan_text

__all__ = [
    "SCHEMA_VERSION",
    "Alert",
    "AlertBus",
    "AlertCode",
    "DeadLetterExhausted",
    "DeadLetterQueue",
    "DeploymentDisabled",
    "DeploymentJournal",
    "FreshnessState",
    "GuardedDeploymentAdapter",
    "IntegrityMismatch",
    "MetricSample",
    "OpsError",
    "PipelineMetrics",
    "PipelineStage",
    "ScannerFinding",
    "SourceObservation",
    "alert_deployment_failed",
    "alert_for_freshness",
    "assert_deployments_enabled",
    "backup_evidence",
    "deployments_enabled",
    "evaluate_freshness",
    "load_operations_config",
    "merge_allowed",
    "recover_or_deploy",
    "restore_evidence",
    "scan_text",
    "verify_digest",
    "verify_file",
    "verify_package",
]
