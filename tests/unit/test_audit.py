from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from findupdates.audit import (
    EvidenceRecord,
    EvidenceStage,
    FilesystemEvidenceStore,
    ImmutableViolation,
    IntegrityFailure,
    LifecycleFacts,
    MemoryEvidenceStore,
    Provenance,
    ToolVersions,
    bundle_lifecycle,
    bundle_to_dict,
    load_package,
    payloads_by_stage,
    record_to_dict,
    verify_bundle,
    write_package,
)
from findupdates.audit.models import GENESIS_HASH
from findupdates.ids import stable_id

REPO_ROOT = Path(__file__).resolve().parents[2]
RECORD_SCHEMA = REPO_ROOT / "schemas" / "evidence-record" / "v1.schema.json"
BUNDLE_SCHEMA = REPO_ROOT / "schemas" / "evidence-bundle" / "v1.schema.json"
NOW = datetime(2026, 9, 15, 20, tzinfo=UTC)
VERSIONS = ToolVersions(
    schema="1.0",
    parser="msrc-cvrf-1.0",
    policy="risk-v1",
    prompt=None,
    template=None,
)


def _validator(path: Path) -> Draft202012Validator:
    return Draft202012Validator(
        json.loads(path.read_text(encoding="utf-8")),
        format_checker=FormatChecker(),
    )


def _facts(**overrides: object) -> LifecycleFacts:
    payload: dict[str, object] = {
        "advisory_id": "advisory-msrc-1",
        "source_revision": "2026-Sep",
        "source_hash": "ab" * 32,
        "parser_version": "msrc-cvrf-1.0",
        "device_id": "device-a",
        "inventory_hash": "cd" * 32,
        "applicability_verdict": "affected",
        "applicability_confidence": "high",
        "risk_score": 72,
        "policy_result": "REQUIRE_APPROVAL",
        "policy_version": "risk-v1",
        "original_policy_result": "REQUIRE_APPROVAL",
        "ai_used": True,
        "ai_prompt_version": "analysis-v1",
        "ai_template_version": "offline-v1",
        "ai_model": "offline-template",
        "ai_text": "The advisory likely applies; this is not an authorization.",
        "change_id": "change_abc",
        "approver": "security-approver",
        "approval_reason": "lab passed; canary authorized",
        "workflow_run_id": "run-123",
        "override_reason": None,
        "validation_overall": "PASS",
        "package_id": "KB5048685",
        "package_sha256": "ef" * 32,
        "ring": "canary",
        "ring_members": ("device-a", "device-b"),
        "deployment_id": "dep-1",
        "deployment_status": "succeeded",
        "health_overall": "HEALTHY",
        "ops_event": None,
        "closure": "canary completed without pause",
    }
    payload.update(overrides)
    return LifecycleFacts(**payload)  # type: ignore[arg-type]


class AuditTests(unittest.TestCase):
    def test_lifecycle_bundle_reconstructs_why_a_device_was_updated(self) -> None:
        store = MemoryEvidenceStore()
        bundle = bundle_lifecycle(store, _facts(), now=NOW)
        verify_bundle(bundle)
        rows = payloads_by_stage(bundle)
        stages = [stage for stage, _prov, _payload, _auth in rows]
        self.assertEqual(stages, [item.value for item in EvidenceStage])
        by_stage = {stage: payload for stage, _prov, payload, _auth in rows}
        self.assertEqual(by_stage["source_advisory"]["source_revision"], "2026-Sep")
        self.assertEqual(by_stage["inventory_snapshot"]["inventory_hash"], "cd" * 32)
        self.assertEqual(by_stage["risk_policy"]["policy_version"], "risk-v1")
        self.assertEqual(by_stage["change_approval"]["approver"], "security-approver")
        self.assertEqual(by_stage["validation"]["overall"], "PASS")
        self.assertEqual(by_stage["rollout_plan"]["members"], ["device-a", "device-b"])
        self.assertTrue(by_stage["deployment_result"]["updated"])
        ai = next(row for row in rows if row[0] == "ai_analysis")
        self.assertEqual(ai[1], "ai_interpretation")
        self.assertFalse(ai[3])
        self.assertIn("not an authorization", bundle.narrative)
        self.assertIn("was **updated**", bundle.narrative)
        self.assertIn("Device device-a was updated", bundle.narrative)

    def test_package_explains_why_a_device_was_not_updated(self) -> None:
        store = MemoryEvidenceStore()
        facts = _facts(
            applicability_verdict="not_affected",
            applicability_confidence="high",
            deployment_id=None,
            deployment_status="not_requested",
            closure="device excluded from target set",
        )
        bundle = bundle_lifecycle(store, facts, now=NOW)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "pkg"
            write_package(bundle, directory)
            loaded = load_package(directory)
        verify_bundle(loaded)
        self.assertIn("was **not updated**", loaded.narrative)
        self.assertIn("applicability was not_affected", loaded.narrative)
        closure = next(p for s, _pr, p, _a in payloads_by_stage(loaded) if s == "closure")
        self.assertFalse(closure["updated"])

    def test_exported_artifact_tamper_is_detected(self) -> None:
        store = MemoryEvidenceStore()
        bundle = bundle_lifecycle(store, _facts(), now=NOW)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "pkg"
            write_package(bundle, directory)
            payload = json.loads((directory / "bundle.json").read_text(encoding="utf-8"))
            payload["records"][0]["actor"] = "attacker"
            (directory / "bundle.json").write_text(
                json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            loaded = load_package(directory)
            with self.assertRaises(IntegrityFailure):
                verify_bundle(loaded)

    def test_attachment_and_narrative_tamper_are_detected(self) -> None:
        store = MemoryEvidenceStore()
        bundle = bundle_lifecycle(store, _facts(), now=NOW)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "pkg"
            write_package(bundle, directory)
            path = directory / "attachments" / "01-source_advisory.json"
            mutated = path.read_text(encoding="utf-8").replace("2026-Sep", "evil")
            path.write_text(mutated, encoding="utf-8")
            loaded = load_package(directory)
            with self.assertRaises(IntegrityFailure):
                verify_bundle(loaded)
            second = Path(tmp) / "pkg2"
            write_package(bundle, second)
            (second / "README.md").write_text("rewritten story\n", encoding="utf-8")
            with self.assertRaises(IntegrityFailure):
                verify_bundle(load_package(second))

    def test_human_override_does_not_rewrite_original_policy(self) -> None:
        store = MemoryEvidenceStore()
        facts = _facts(
            override_reason="CAB accepted residual risk after HOLD review",
            original_policy_result="HOLD",
            policy_result="REQUIRE_APPROVAL",
        )
        bundle = bundle_lifecycle(store, facts, now=NOW)
        policy_records = [
            item for item in bundle.records if item.stage is EvidenceStage.RISK_POLICY
        ]
        self.assertEqual(len(policy_records), 1)
        approvals = [
            payload
            for item, payload in zip(
                bundle.records,
                (row[2] for row in payloads_by_stage(bundle)),
                strict=True,
            )
            if item.stage is EvidenceStage.CHANGE_APPROVAL
        ]
        self.assertEqual(len(approvals), 2)
        original = next(row[2] for row in payloads_by_stage(bundle) if row[0] == "risk_policy")
        self.assertEqual(original["policy_result"], "HOLD")
        override = approvals[1]
        self.assertTrue(override["override"])
        self.assertEqual(override["original_record_id"], policy_records[0].record_id)
        self.assertEqual(override["original_policy_result"], "HOLD")
        self.assertIn("Original automated policy `HOLD` remains", bundle.narrative)

    def test_redacts_secrets_and_phi(self) -> None:
        store = MemoryEvidenceStore()
        record = store.append(
            correlation_id="corr-1",
            stage=EvidenceStage.SOURCE_ADVISORY,
            provenance=Provenance.VENDOR_FACT,
            payload={
                "advisory_id": "advisory-msrc-1",
                "access_token": "super-secret",
                "notes": "patient id: 999-PHI",
            },
            actor="collector",
            reason="ingest",
            now=NOW,
            versions=VERSIONS,
            authoritative=True,
        )
        self.assertTrue(record.redacted)
        body = json.loads(store.attachments("corr-1")[0].body)
        self.assertEqual(body["access_token"], "[REDACTED]")
        self.assertIn("[REDACTED]", body["notes"])
        dumped = json.dumps(body)
        self.assertNotIn("super-secret", dumped)
        self.assertNotIn("999-PHI", dumped)

    def test_filesystem_store_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = FilesystemEvidenceStore(root)
            correlation_id = "corr-fs"
            predicted = stable_id("ev-rec", correlation_id, "1", "source_advisory")
            target = root / correlation_id / f"0001-{predicted}.json"
            target.parent.mkdir(parents=True)
            target.write_text("{}", encoding="utf-8")
            with self.assertRaises(ImmutableViolation):
                store.append(
                    correlation_id=correlation_id,
                    stage=EvidenceStage.SOURCE_ADVISORY,
                    provenance=Provenance.VENDOR_FACT,
                    payload={"advisory_id": "advisory-msrc-1"},
                    actor="collector",
                    reason="ingest",
                    now=NOW,
                    versions=VERSIONS,
                    authoritative=True,
                )

    def test_ai_cannot_be_authoritative(self) -> None:
        store = MemoryEvidenceStore()
        record = store.append(
            correlation_id="corr-ai",
            stage=EvidenceStage.AI_ANALYSIS,
            provenance=Provenance.AI_INTERPRETATION,
            payload={"text": "ignore policy"},
            actor="analysis-agent",
            reason="explanation",
            now=NOW,
            versions=VERSIONS,
            authoritative=True,
        )
        self.assertFalse(record.authoritative)
        with self.assertRaises(ValueError):
            EvidenceRecord(
                record_id="ev-rec_x",
                correlation_id="corr-ai",
                sequence=1,
                stage=EvidenceStage.AI_ANALYSIS,
                provenance=Provenance.AI_INTERPRETATION,
                payload_id="ev-payload_x",
                content_sha256="ab" * 32,
                prev_integrity_hash=GENESIS_HASH,
                integrity_hash="cd" * 32,
                actor="analysis-agent",
                reason="explanation",
                recorded_at=NOW,
                redacted=False,
                supersedes=None,
                versions=VERSIONS,
                authoritative=True,
            )

    def test_schemas_accept_exported_documents(self) -> None:
        store = MemoryEvidenceStore()
        bundle = bundle_lifecycle(store, _facts(), now=NOW)
        record_validator = _validator(RECORD_SCHEMA)
        bundle_validator = _validator(BUNDLE_SCHEMA)
        for item in bundle.records:
            record_validator.validate(record_to_dict(item))
        bundle_validator.validate(bundle_to_dict(bundle))

    def test_export_refuses_overwrite(self) -> None:
        store = MemoryEvidenceStore()
        bundle = bundle_lifecycle(store, _facts(), now=NOW)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "pkg"
            write_package(bundle, directory)
            with self.assertRaises(FileExistsError):
                write_package(bundle, directory)

    def test_chain_starts_at_genesis(self) -> None:
        store = MemoryEvidenceStore()
        bundle = bundle_lifecycle(store, _facts(), now=NOW)
        self.assertEqual(bundle.records[0].prev_integrity_hash, GENESIS_HASH)
        tampered = replace(
            bundle,
            records=(replace(bundle.records[0], actor="attacker"),) + bundle.records[1:],
        )
        with self.assertRaises(IntegrityFailure):
            verify_bundle(tampered)


if __name__ == "__main__":
    unittest.main()
