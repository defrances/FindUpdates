from __future__ import annotations

import hashlib
import logging
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path

from findupdates.audit import MemoryEvidenceStore, bundle_lifecycle
from findupdates.audit.lifecycle import LifecycleFacts
from findupdates.deployment import (
    AuthorizationEvidence,
    DeploymentTarget,
    MockDeploymentAdapter,
    OidcCredential,
    PackageIdentity,
    RolloutPolicy,
    UpdateKind,
    prepare,
)
from findupdates.logging import (
    CorrelationFormatter,
    get_correlation_id,
    get_log_context,
    set_correlation_id,
    set_log_context,
)
from findupdates.ops import (
    AlertBus,
    AlertCode,
    DeadLetterExhausted,
    DeadLetterQueue,
    DeploymentDisabled,
    DeploymentJournal,
    FreshnessState,
    GuardedDeploymentAdapter,
    IntegrityMismatch,
    MetricSample,
    PipelineMetrics,
    PipelineStage,
    ScannerFinding,
    SourceObservation,
    alert_deployment_failed,
    alert_for_freshness,
    backup_evidence,
    evaluate_freshness,
    load_operations_config,
    merge_allowed,
    recover_or_deploy,
    restore_evidence,
    scan_text,
    verify_digest,
)
from findupdates.ops.errors import OpsError
from findupdates.ops.workflows import (
    has_pull_request_trigger,
    load_workflow,
    unpinned_actions,
    workflow_has_contents_read,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 9, 15, 20, tzinfo=UTC)
PACKAGE = PackageIdentity(
    kind=UpdateKind.OS,
    package_id="KB5048685",
    version="10.0.19045.5011",
    sha256="ab" * 32,
)


def _config(**overrides: object) -> dict[str, object]:
    payload = load_operations_config()
    payload.update(overrides)
    return payload


def _evidence() -> AuthorizationEvidence:
    return AuthorizationEvidence(
        advisory_ids=("advisory-msrc-1",),
        risk_assessment_id="risk_abc",
        policy_result="REQUIRE_APPROVAL",
        change_idempotency_key="change_abc",
        validation_result_id="validation_abc",
        approver="security-approver",
        approved_at=NOW,
    )


def _credential() -> OidcCredential:
    return OidcCredential(
        audience="api://findupdates-deployment",
        expires_at=NOW + timedelta(minutes=5),
        token="oidc-short-lived-token",
    )


def _request():
    return prepare(
        PACKAGE,
        (DeploymentTarget("device-a", "mock-intune"),),
        RolloutPolicy("canary", "ring-0"),
        _evidence(),
    )


def _facts() -> LifecycleFacts:
    return LifecycleFacts(
        advisory_id="advisory-msrc-1",
        source_revision="2026-Sep",
        source_hash="ab" * 32,
        parser_version="msrc-cvrf-1.0",
        device_id="device-a",
        inventory_hash="cd" * 32,
        applicability_verdict="affected",
        applicability_confidence="high",
        risk_score=72,
        policy_result="REQUIRE_APPROVAL",
        policy_version="risk-v1",
        original_policy_result="REQUIRE_APPROVAL",
        ai_used=False,
        ai_prompt_version=None,
        ai_template_version=None,
        ai_model=None,
        ai_text=None,
        change_id="change_abc",
        approver="security-approver",
        approval_reason="lab passed",
        workflow_run_id="run-123",
        override_reason=None,
        validation_overall="PASS",
        package_id="KB5048685",
        package_sha256="ef" * 32,
        ring="canary",
        ring_members=("device-a",),
        deployment_id="dep-1",
        deployment_status="succeeded",
        health_overall="HEALTHY",
        ops_event=None,
        closure="closed",
    )


class OperationsTests(unittest.TestCase):
    def test_kill_switch_blocks_deploy_but_collection_continues(self) -> None:
        config = _config(deployments_enabled=False, disabled_reason="emergency stop")
        metrics = PipelineMetrics()
        metrics.record(
            MetricSample(
                correlation_id="corr-1",
                advisory_id="advisory-msrc-1",
                stage=PipelineStage.COLLECT,
                name="collector_success",
                value=1,
                recorded_at=NOW,
            )
        )
        self.assertEqual(metrics.total("collector_success", correlation_id="corr-1"), 1)
        guarded = GuardedDeploymentAdapter(MockDeploymentAdapter(), config)
        with self.assertRaises(DeploymentDisabled):
            guarded.deploy(_request(), credential=_credential(), now=NOW)
        env_guard = GuardedDeploymentAdapter(
            MockDeploymentAdapter(),
            _config(deployments_enabled=True),
            environ={"FINDUPDATES_DEPLOYMENTS_ENABLED": "false"},
        )
        with self.assertRaises(DeploymentDisabled):
            env_guard.deploy(_request(), credential=_credential(), now=NOW)

    def test_stale_and_unobserved_sources_alert_and_are_not_healthy(self) -> None:
        config = load_operations_config()
        bus = AlertBus()
        stale = SourceObservation(
            source="msrc",
            last_success_at=NOW - timedelta(hours=72),
            last_error=None,
            observed_at=NOW,
        )
        verdict = evaluate_freshness(stale, config, now=NOW)
        self.assertIs(verdict.state, FreshnessState.STALE)
        self.assertFalse(verdict.healthy)
        alert = alert_for_freshness(verdict, stale, correlation_id="corr-1", now=NOW)
        assert alert is not None
        bus.emit(alert)
        missing = SourceObservation("kev", None, None, NOW)
        missing_verdict = evaluate_freshness(missing, config, now=NOW)
        self.assertIs(missing_verdict.state, FreshnessState.UNOBSERVED)
        self.assertFalse(missing_verdict.healthy)
        unobserved = alert_for_freshness(missing_verdict, missing, correlation_id="corr-1", now=NOW)
        assert unobserved is not None
        bus.emit(unobserved)
        failed = SourceObservation("intel", NOW, "timeout", NOW)
        failed_verdict = evaluate_freshness(failed, config, now=NOW)
        failed_alert = alert_for_freshness(failed_verdict, failed, correlation_id="corr-1", now=NOW)
        assert failed_alert is not None
        bus.emit(failed_alert)
        self.assertIn(AlertCode.SOURCE_STALE, bus.codes())
        self.assertIn(AlertCode.SOURCE_UNOBSERVED, bus.codes())
        self.assertIn(AlertCode.COLLECTOR_FAILED, bus.codes())

    def test_deployment_failure_and_missing_metrics_are_not_healthy(self) -> None:
        bus = AlertBus()
        bus.emit(
            alert_deployment_failed(
                correlation_id="corr-1",
                advisory_id="advisory-msrc-1",
                reason="adapter timeout",
                now=NOW,
            )
        )
        metrics = PipelineMetrics()
        healthy = metrics.observability_healthy(
            "corr-1",
            (PipelineStage.COLLECT, PipelineStage.DEPLOYMENT),
            missing_is_healthy=False,
        )
        self.assertFalse(healthy)
        self.assertIs(bus.codes()[0], AlertCode.DEPLOYMENT_FAILED)
        with self.assertRaises(OpsError):
            metrics.observability_healthy(
                "corr-1",
                (PipelineStage.COLLECT,),
                missing_is_healthy=True,
            )

    def test_metrics_correlate_one_advisory_lifecycle(self) -> None:
        set_correlation_id("corr-adv")
        set_log_context(advisory_id="advisory-msrc-1", stage="collect")
        metrics = PipelineMetrics()
        for stage in (
            PipelineStage.COLLECT,
            PipelineStage.RISK,
            PipelineStage.VALIDATION,
            PipelineStage.DEPLOYMENT,
            PipelineStage.EVIDENCE,
        ):
            metrics.record(
                MetricSample(
                    correlation_id="corr-adv",
                    advisory_id="advisory-msrc-1",
                    stage=stage,
                    name=f"{stage.value}_count",
                    value=1,
                    recorded_at=NOW,
                )
            )
        self.assertEqual(get_correlation_id(), "corr-adv")
        self.assertEqual(get_log_context()[1], "advisory-msrc-1")
        self.assertTrue(
            metrics.observability_healthy(
                "corr-adv",
                (PipelineStage.COLLECT, PipelineStage.DEPLOYMENT, PipelineStage.EVIDENCE),
                missing_is_healthy=False,
            )
        )

    def test_logs_redact_secrets_and_keep_correlation(self) -> None:
        set_correlation_id("corr-log")
        set_log_context(advisory_id="advisory-msrc-1", stage="collect")
        stream = StringIO()
        logger = logging.getLogger("findupdates.ops.test")
        handler = logging.StreamHandler(stream)
        handler.setFormatter(CorrelationFormatter())
        logger.handlers = [handler]
        logger.setLevel(logging.INFO)
        logger.propagate = False
        logger.info("token=Bearer super-secret-token")
        line = stream.getvalue()
        self.assertIn("correlation_id=corr-log", line)
        self.assertIn("advisory_id=advisory-msrc-1", line)
        self.assertIn("[REDACTED]", line)
        self.assertNotIn("super-secret-token", line)

    def test_recovery_does_not_duplicate_deployment(self) -> None:
        request = _request()
        with tempfile.TemporaryDirectory() as tmp:
            journal_path = Path(tmp) / "journal.jsonl"
            first = MockDeploymentAdapter()
            journal = DeploymentJournal(journal_path)
            result, recovered = recover_or_deploy(
                first, journal, request, credential=_credential(), now=NOW
            )
            self.assertFalse(recovered)
            self.assertFalse(result.duplicate)
            crashed = MockDeploymentAdapter()
            restored = DeploymentJournal(journal_path)
            replay, recovered = recover_or_deploy(
                crashed, restored, request, credential=_credential(), now=NOW
            )
            self.assertTrue(recovered)
            self.assertEqual(replay.deployment_id, result.deployment_id)
            self.assertEqual(len(crashed._by_id), 0)

    def test_dead_letter_retries_then_alerts(self) -> None:
        queue = DeadLetterQueue(load_operations_config())
        event = queue.submit(
            correlation_id="corr-1",
            stage=PipelineStage.NOTIFICATION,
            payload={"advisory_id": "advisory-msrc-1"},
        )
        attempts = {"n": 0}

        def boom(_event: object) -> None:
            attempts["n"] += 1
            raise RuntimeError("webhook 503")

        with self.assertRaises(DeadLetterExhausted) as ctx:
            for _ in range(5):
                queue.retry(event, boom, now=NOW)
        self.assertEqual(attempts["n"], 3)
        self.assertEqual(ctx.exception.alert.code, AlertCode.DEAD_LETTER)
        self.assertEqual(len(queue.poisoned()), 1)

    def test_evidence_backup_restore_and_package_hash(self) -> None:
        store = MemoryEvidenceStore()
        bundle = bundle_lifecycle(store, _facts(), now=NOW)
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "backup"
            backup_evidence(
                store,
                bundle.correlation_id,
                dest,
                now=NOW,
                narrative=bundle.narrative,
            )
            restored = restore_evidence(dest)
            self.assertEqual(restored.chain_tip, bundle.chain_tip)
        digest = hashlib.sha256(b"payload").hexdigest()
        verify_digest(b"payload", digest)
        with self.assertRaises(IntegrityMismatch):
            verify_digest(b"payload", "ab" * 32)

    def test_scanner_high_finding_blocks_merge(self) -> None:
        config = load_operations_config()
        self.assertTrue(merge_allowed((), config))
        blocked = merge_allowed(
            (ScannerFinding("high", "GHSA-test", "requirements-dev.lock"),),
            config,
        )
        self.assertFalse(blocked)
        self.assertIn("github_pat", scan_text("ghp_" + "a" * 36))
        self.assertIn("phi", scan_text("mrn 12345"))
        self.assertEqual(scan_text("token=safe"), ())

    def test_workflows_are_pinned_least_privilege_and_pr_isolated(self) -> None:
        ci = load_workflow(REPO_ROOT, "ci.yml")
        deps = load_workflow(REPO_ROOT, "dependency-review.yml")
        promo = load_workflow(REPO_ROOT, "change-promotion.yml")
        self.assertEqual(unpinned_actions(ci), ())
        self.assertEqual(unpinned_actions(deps), ())
        self.assertEqual(unpinned_actions(promo), ())
        self.assertTrue(workflow_has_contents_read(ci))
        self.assertTrue(has_pull_request_trigger(ci))
        self.assertFalse(has_pull_request_trigger(promo))
        self.assertNotIn("id-token", promo.split("jobs:")[0])
        self.assertIn("id-token: write", promo)
        self.assertIn("persist-credentials: false", ci)
        self.assertIn("No pull_request trigger", promo)


if __name__ == "__main__":
    unittest.main()
