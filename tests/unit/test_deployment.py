from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from findupdates.deployment import (
    OEM_CAPABILITIES,
    WINDOWS_CAPABILITIES,
    AuthError,
    AuthorizationEvidence,
    AuthorizationMissing,
    BackendRejected,
    DeploymentStatus,
    DeploymentTarget,
    ErrorCode,
    FirmwareNotOemQualified,
    MockDeploymentAdapter,
    OidcCredential,
    PackageIdentity,
    PackageMismatch,
    PartialFailure,
    RollbackUnsupported,
    RolloutPolicy,
    TargetMismatch,
    UnsupportedUpdateKind,
    UpdateKind,
    dict_to_request,
    prepare,
    request_to_dict,
    result_to_dict,
    target_set_hash,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
REQUEST_SCHEMA = REPO_ROOT / "schemas" / "deployment-request" / "v1.schema.json"
RESULT_SCHEMA = REPO_ROOT / "schemas" / "deployment-result" / "v1.schema.json"
NOW = datetime(2026, 9, 15, 18, tzinfo=UTC)
OS_PACKAGE = PackageIdentity(
    kind=UpdateKind.OS,
    package_id="KB5048685",
    version="10.0.19045.5011",
    sha256="ab" * 32,
)
FIRMWARE_PACKAGE = PackageIdentity(
    kind=UpdateKind.FIRMWARE,
    package_id="intel-me-unqualified",
    version="16.1.25",
    sha256="cd" * 32,
)
TARGETS = (
    DeploymentTarget("device-a", "mock-intune"),
    DeploymentTarget("device-b", "mock-intune"),
)
OEM_TARGETS = (
    DeploymentTarget("device-a", "mock-oem-agent"),
    DeploymentTarget("device-b", "mock-oem-agent"),
)


def _validator(path: Path) -> Draft202012Validator:
    return Draft202012Validator(
        json.loads(path.read_text(encoding="utf-8")),
        format_checker=FormatChecker(),
    )


def _evidence(*, policy: str = "REQUIRE_APPROVAL") -> AuthorizationEvidence:
    return AuthorizationEvidence(
        advisory_ids=("advisory-msrc-1",),
        risk_assessment_id="risk_abc",
        policy_result=policy,
        change_idempotency_key="change_abc",
        validation_result_id="validation_abc",
        approver="security-approver",
        approved_at=NOW,
    )


def _credential(*, expired: bool = False) -> OidcCredential:
    expiry = NOW - timedelta(minutes=1) if expired else NOW + timedelta(minutes=5)
    return OidcCredential(
        audience="api://findupdates-deployment",
        expires_at=expiry,
        token="oidc-short-lived-token",
    )


def _os_request(**overrides: object):
    kwargs = {
        "update": OS_PACKAGE,
        "targets": TARGETS,
        "rollout": RolloutPolicy("canary", "ring-0"),
        "evidence": _evidence(),
        "dry_run": False,
        "oem_qualified": False,
    }
    kwargs.update(overrides)
    return prepare(**kwargs)  # type: ignore[arg-type]


class DeploymentAdapterTests(unittest.TestCase):
    def test_authorized_windows_lifecycle(self) -> None:
        adapter = MockDeploymentAdapter()
        request = _os_request()
        adapter.validate_request(request)
        submitted = adapter.deploy(request, credential=_credential(), now=NOW)
        self.assertIs(submitted.status, DeploymentStatus.IN_PROGRESS)
        self.assertFalse(submitted.duplicate)
        self.assertEqual(adapter.capabilities(), WINDOWS_CAPABILITIES)
        self.assertTrue(adapter.capabilities().supports_pause)
        self.assertTrue(adapter.capabilities().supports_rollback)

        paused = adapter.pause(submitted.deployment_id, credential=_credential(), now=NOW)
        self.assertIs(paused.status, DeploymentStatus.PAUSED)
        resumed = adapter.resume(submitted.deployment_id, credential=_credential(), now=NOW)
        self.assertIs(resumed.status, DeploymentStatus.IN_PROGRESS)
        done = adapter.complete(submitted.deployment_id, now=NOW)
        self.assertIs(done.status, DeploymentStatus.SUCCEEDED)
        rolled = adapter.rollback_or_uninstall(
            submitted.deployment_id, credential=_credential(), now=NOW
        )
        self.assertIs(rolled.status, DeploymentStatus.ROLLED_BACK)

        errors = list(_validator(REQUEST_SCHEMA).iter_errors(request_to_dict(request)))
        self.assertEqual([], errors)
        errors = list(_validator(RESULT_SCHEMA).iter_errors(result_to_dict(done)))
        self.assertEqual([], errors)
        self.assertEqual(done.audit.approver, "security-approver")
        self.assertEqual(done.audit.validation_result_id, "validation_abc")
        self.assertEqual(done.package_id, OS_PACKAGE.package_id)
        self.assertEqual(done.package_sha256, OS_PACKAGE.sha256)
        self.assertEqual(done.target_device_ids, ("device-a", "device-b"))
        self.assertEqual(done.audit.credential_kind, "oidc")

    def test_duplicate_idempotency_key_does_not_reinstall(self) -> None:
        adapter = MockDeploymentAdapter()
        request = _os_request()
        first = adapter.deploy(request, credential=_credential(), now=NOW)
        second = adapter.deploy(request, credential=_credential(), now=NOW)
        self.assertEqual(first.deployment_id, second.deployment_id)
        self.assertTrue(second.duplicate)
        self.assertEqual(len(adapter._by_id), 1)

    def test_retry_same_package_and_targets_does_not_duplicate_install(self) -> None:
        adapter = MockDeploymentAdapter()
        first = adapter.deploy(_os_request(), credential=_credential(), now=NOW)
        replay = prepare(
            OS_PACKAGE,
            TARGETS,
            RolloutPolicy("canary", "ring-0"),
            _evidence(),
            idempotency_key="deploy_different-key-value",
        )
        second = adapter.deploy(replay, credential=_credential(), now=NOW)
        self.assertEqual(first.deployment_id, second.deployment_id)
        self.assertTrue(second.duplicate)

    def test_target_hash_mismatch_is_rejected(self) -> None:
        adapter = MockDeploymentAdapter()
        request = _os_request()
        extra = DeploymentTarget("device-c", "mock-intune")
        widened = prepare(
            request.update,
            (*request.targets, extra),
            request.rollout,
            request.evidence,
            dry_run=request.dry_run,
            request_id=request.request_id,
            idempotency_key=request.idempotency_key,
        )
        tampered = dict_to_request(
            {
                **request_to_dict(widened),
                "approved_target_set_hash": request.approved_target_set_hash,
            }
        )
        self.assertNotEqual(tampered.approved_target_set_hash, target_set_hash(tampered.device_ids))
        with self.assertRaises(TargetMismatch):
            adapter.validate_request(tampered)

    def test_package_identity_mismatch_is_rejected(self) -> None:
        adapter = MockDeploymentAdapter(expected_package=OS_PACKAGE)
        other = PackageIdentity(
            kind=UpdateKind.OS,
            package_id="KB5048685",
            version="10.0.19045.5011",
            sha256="ef" * 32,
        )
        request = _os_request(update=other)
        with self.assertRaises(PackageMismatch):
            adapter.deploy(request, credential=_credential(), now=NOW)

    def test_missing_credential_is_rejected(self) -> None:
        adapter = MockDeploymentAdapter()
        with self.assertRaises(AuthorizationMissing):
            adapter.deploy(_os_request(), credential=None, now=NOW)

    def test_analysis_only_policy_is_not_authorization(self) -> None:
        adapter = MockDeploymentAdapter()
        request = _os_request(evidence=_evidence(policy="ALLOW_ANALYSIS"))
        with self.assertRaises(AuthorizationMissing):
            adapter.validate_request(request)

    def test_hold_cannot_build_authorized_evidence(self) -> None:
        with self.assertRaises(ValueError):
            _evidence(policy="HOLD")

    def test_expired_oidc_credential_is_auth_error(self) -> None:
        adapter = MockDeploymentAdapter()
        with self.assertRaises(AuthError):
            adapter.deploy(_os_request(), credential=_credential(expired=True), now=NOW)

    def test_firmware_without_oem_qualification_is_rejected(self) -> None:
        adapter = MockDeploymentAdapter(OEM_CAPABILITIES)
        request = prepare(
            FIRMWARE_PACKAGE,
            OEM_TARGETS,
            RolloutPolicy("lab", "ring-0"),
            _evidence(),
            oem_qualified=False,
        )
        with self.assertRaises(FirmwareNotOemQualified):
            adapter.deploy(request, credential=_credential(), now=NOW)

    def test_windows_adapter_rejects_firmware(self) -> None:
        adapter = MockDeploymentAdapter()
        request = prepare(
            FIRMWARE_PACKAGE,
            TARGETS,
            RolloutPolicy("lab", "ring-0"),
            _evidence(),
            oem_qualified=True,
        )
        with self.assertRaises(UnsupportedUpdateKind):
            adapter.validate_request(request)

    def test_oem_rollback_is_explicitly_unsupported(self) -> None:
        adapter = MockDeploymentAdapter(OEM_CAPABILITIES)
        request = prepare(
            FIRMWARE_PACKAGE,
            OEM_TARGETS,
            RolloutPolicy("lab", "ring-0"),
            _evidence(),
            oem_qualified=True,
        )
        submitted = adapter.deploy(request, credential=_credential(), now=NOW)
        self.assertFalse(adapter.capabilities().supports_rollback)
        with self.assertRaises(RollbackUnsupported):
            adapter.rollback_or_uninstall(
                submitted.deployment_id, credential=_credential(), now=NOW
            )
        self.assertIs(adapter.status(submitted.deployment_id).status, DeploymentStatus.IN_PROGRESS)

    def test_oem_pause_is_rejected(self) -> None:
        adapter = MockDeploymentAdapter(OEM_CAPABILITIES)
        request = prepare(
            FIRMWARE_PACKAGE,
            OEM_TARGETS,
            RolloutPolicy("lab", "ring-0"),
            _evidence(),
            oem_qualified=True,
        )
        submitted = adapter.deploy(request, credential=_credential(), now=NOW)
        with self.assertRaises(BackendRejected):
            adapter.pause(submitted.deployment_id, credential=_credential(), now=NOW)

    def test_dry_run_succeeds_without_install_index(self) -> None:
        adapter = MockDeploymentAdapter()
        planned = adapter.deploy(_os_request(dry_run=True), credential=_credential(), now=NOW)
        self.assertTrue(planned.dry_run)
        self.assertIs(planned.status, DeploymentStatus.SUCCEEDED)
        live = adapter.deploy(_os_request(dry_run=False), credential=_credential(), now=NOW)
        self.assertNotEqual(planned.deployment_id, live.deployment_id)
        self.assertFalse(live.duplicate)
        self.assertIs(live.status, DeploymentStatus.IN_PROGRESS)

    def test_partial_failure_does_not_claim_success(self) -> None:
        adapter = MockDeploymentAdapter(inject_error=ErrorCode.PARTIAL_FAILURE)
        with self.assertRaises(PartialFailure):
            adapter.deploy(_os_request(), credential=_credential(), now=NOW)
        self.assertEqual(adapter._by_id, {})

    def test_audit_redacts_secrets_and_omits_token(self) -> None:
        adapter = MockDeploymentAdapter()
        request = _os_request()
        result = adapter.deploy(request, credential=_credential(), now=NOW)
        blob = json.dumps({"request": request_to_dict(request), "result": result_to_dict(result)})
        self.assertNotIn("oidc-short-lived-token", blob)
        self.assertNotIn("patient", blob.lower())
        self.assertNotIn("mrn", blob.lower())
        snapshot = json.dumps(adapter.backend_audit)
        self.assertIn("[REDACTED]", snapshot)
        self.assertNotIn("super-secret-token", snapshot)

    def test_cancel_in_progress_job(self) -> None:
        adapter = MockDeploymentAdapter()
        submitted = adapter.deploy(_os_request(), credential=_credential(), now=NOW)
        cancelled = adapter.cancel(submitted.deployment_id, credential=_credential(), now=NOW)
        self.assertIs(cancelled.status, DeploymentStatus.CANCELLED)


if __name__ == "__main__":
    unittest.main()
