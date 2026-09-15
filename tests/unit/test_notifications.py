from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from findupdates.applicability import evaluate
from findupdates.changerecords import build_change_record
from findupdates.inventory import (
    ClinicalCriticality,
    DeviceInventory,
    NetworkExposure,
    OperatingSystem,
    VerificationState,
    evaluate_freshness,
)
from findupdates.normalization import (
    AffectedProduct,
    Architecture,
    CvssRecord,
    CvssVersion,
    NormalizedSourceRecord,
    PackageId,
    PackageKind,
    ProductStatus,
    Provenance,
    Remediation,
    RemediationKind,
    TriState,
    UpdateAdvisory,
    Vendor,
    VendorSeverity,
    normalize_source_record,
)
from findupdates.notifications import (
    DeliveryStatus,
    GitHubCommentChannel,
    MappingWebhookTransport,
    NotificationKind,
    NotificationService,
    WebhookChannel,
    canonical_event_json,
    event_to_dict,
    render_markdown,
)
from findupdates.risk import assess

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "schemas" / "notification-event" / "v1.schema.json"
NOW = datetime(2026, 9, 15, 12, tzinfo=UTC)
ISSUE_URL = "https://github.com/defrances/FindUpdates/issues/99"
WINDOWS_CPE = "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:x64:*"
_FIX = (Remediation(RemediationKind.VENDOR_FIX, "vendor patch", None, None),)


def _os() -> OperatingSystem:
    return OperatingSystem(
        product="Windows 11 IoT Enterprise",
        edition="IoT Enterprise",
        version="24H2",
        build="10.0.22621.2500",
        architecture="x64",
        vendor_product_id="windows_11",
        cpe=WINDOWS_CPE,
        verification_state=VerificationState.VERIFIED,
    )


def _device(
    *,
    device_id: str = "SYNTHETIC-MED-001",
    clinical: ClinicalCriticality = ClinicalCriticality.CRITICAL,
    exposure: NetworkExposure = NetworkExposure.INTERNET_EXPOSED,
    model: str = "ImagingStation-X200",
) -> DeviceInventory:
    collected = NOW - timedelta(hours=2)
    freshness = evaluate_freshness(
        inventory_timestamp=collected,
        evaluated_at=NOW,
        max_age=timedelta(hours=24),
    )
    return DeviceInventory(
        device_id=device_id,
        manufacturer="Example Medical Systems",
        model=model,
        device_role="imaging-workstation",
        clinical_criticality=clinical,
        network_exposure=exposure,
        deployment_group="lab-ring-0",
        os=_os(),
        hardware_components=(),
        software_components=(),
        inventory_timestamp=collected,
        inventory_source="synthetic-lab-agent",
        source_confidence=VerificationState.VERIFIED,
        freshness_state=freshness,
        freshness_evaluated_at=NOW,
        freshness_max_age_hours=24,
    )


def _windows_product() -> AffectedProduct:
    return AffectedProduct(
        vendor="microsoft",
        product="Windows 11",
        version_range=">=10.0.22621 <10.0.22631",
        builds=("22621", "22631"),
        architectures=(Architecture.X64,),
        vendor_product_id="windows_11",
        cpe=WINDOWS_CPE,
        status=ProductStatus.AFFECTED,
    )


def _advisory(
    *,
    vendor_advisory_id: str = "ADV260915",
    exploited: TriState = TriState.TRUE,
    severity: VendorSeverity = VendorSeverity.CRITICAL,
    cvss: tuple[CvssRecord, ...] | None = None,
    remediations: tuple[Remediation, ...] = (),
    products: tuple[AffectedProduct, ...] | None = None,
) -> UpdateAdvisory:
    records = cvss
    if records is None:
        records = (
            CvssRecord(
                CvssVersion.V3_1,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                9.8,
                "nvd:nvd.nist.gov",
            ),
        )
    record = NormalizedSourceRecord(
        vendor=Vendor.MICROSOFT,
        source="test",
        vendor_advisory_id=vendor_advisory_id,
        title="Windows Kernel Elevation of Privilege Vulnerability",
        published_at=datetime(2026, 9, 8, 17, tzinfo=UTC),
        provenance=Provenance(
            source_url="https://example.invalid/advisory",
            raw_sha256="f" * 64,
            retrieved_at=NOW,
            content_type="application/json",
        ),
        cve_ids=("CVE-2026-12345",),
        package_ids=(PackageId(PackageKind.KB, "KB5060001"),),
        vendor_severity=severity,
        known_exploited=exploited,
        cvss=records,
        remediations=remediations,
        affected_products=(_windows_product(),) if products is None else products,
    )
    return normalize_source_record(record)


def _pipeline(
    *,
    devices: tuple[DeviceInventory, ...] | None = None,
    **advisory_kwargs: object,
):
    advisory = _advisory(**advisory_kwargs)
    inventory = devices or (_device(),)
    apps = tuple(evaluate(advisory, item, now=NOW) for item in inventory)
    risks = tuple(
        assess(advisory, item, app, now=NOW) for item, app in zip(inventory, apps, strict=True)
    )
    change = build_change_record(advisory, inventory, apps, risks, now=NOW)
    return advisory, inventory, apps, risks, change


def _service(
    webhook: WebhookChannel | None = None,
) -> tuple[NotificationService, GitHubCommentChannel]:
    github = GitHubCommentChannel()
    channels = {"github": github}
    if webhook is not None:
        channels["webhook"] = webhook
    return NotificationService(channels), github


class NotificationServiceTests(unittest.TestCase):
    def test_high_advisory_emits_one_logical_notification(self) -> None:
        advisory, devices, apps, risks, change = _pipeline()
        self.assertIn(risks[0].severity.value, {"HIGH", "CRITICAL", "EMERGENCY"})
        transport = MappingWebhookTransport({"https://example.invalid/hook": [200]})
        webhook = WebhookChannel("https://example.invalid/hook", transport=transport)
        service, github = _service(webhook)
        result = service.notify_advisory(
            advisory, devices, apps, risks, change, now=NOW, change_record_url=ISSUE_URL
        )
        self.assertFalse(result.suppressed)
        self.assertIsNotNone(result.event)
        assert result.event is not None
        self.assertEqual(len(github.sink), 1)
        self.assertEqual(len(transport.bodies), 1)
        self.assertEqual({item.channel for item in result.deliveries}, {"github", "webhook"})
        self.assertTrue(all(item.status is DeliveryStatus.DELIVERED for item in result.deliveries))
        self.assertTrue(result.event.acknowledgement_required)
        errors = list(
            Draft202012Validator(
                json.loads(SCHEMA_PATH.read_text(encoding="utf-8")),
                format_checker=FormatChecker(),
            ).iter_errors(event_to_dict(result.event))
        )
        self.assertEqual([], errors)
        body = render_markdown(result.event)
        self.assertIn("CVE-2026-12345", body)
        self.assertIn("KB5060001", body)
        self.assertIn(ISSUE_URL, body)

    def test_unchanged_rescan_is_suppressed(self) -> None:
        bundle = _pipeline()
        service, github = _service()
        first = service.notify_advisory(*bundle, now=NOW, change_record_url=ISSUE_URL)
        second = service.notify_advisory(
            *bundle, now=NOW + timedelta(hours=1), change_record_url=ISSUE_URL
        )
        self.assertFalse(first.suppressed)
        self.assertTrue(second.suppressed)
        self.assertEqual(second.deliveries, ())
        self.assertEqual(len(github.sink), 1)

    def test_device_count_increase_is_material(self) -> None:
        service, _github = _service()
        first = _pipeline(devices=(_device(),))
        service.notify_advisory(*first, now=NOW, change_record_url=ISSUE_URL)
        second = _pipeline(devices=(_device(), _device(device_id="SYNTHETIC-MED-002")))
        result = service.notify_advisory(*second, now=NOW, change_record_url=ISSUE_URL)
        self.assertFalse(result.suppressed)
        assert result.event is not None
        self.assertIsNotNone(result.event.previous_state)
        assert result.event.previous_state is not None
        self.assertEqual(result.event.previous_state.affected_device_count, 1)
        self.assertEqual(result.event.affected_device_count, 2)

    def test_operational_failure_notifies_and_retries_webhook(self) -> None:
        _advisory_obj, devices, apps, risks, change = _pipeline()
        transport = MappingWebhookTransport({"https://example.invalid/hook": [503, 200]})
        webhook = WebhookChannel("https://example.invalid/hook", transport=transport)
        service, _github = _service(webhook)
        result = service.notify_operational_failure(
            change,
            now=NOW,
            change_record_url=ISSUE_URL,
            reason="validation job failed",
        )
        self.assertIs(result.event.kind, NotificationKind.OPERATIONAL_FAILURE)
        webhook_delivery = next(item for item in result.deliveries if item.channel == "webhook")
        self.assertIs(webhook_delivery.status, DeliveryStatus.DELIVERED)
        self.assertEqual(webhook_delivery.attempts, 2)
        repeat = service.notify_operational_failure(
            change,
            now=NOW + timedelta(minutes=1),
            change_record_url=ISSUE_URL,
            reason="validation job failed",
        )
        self.assertTrue(repeat.suppressed)

    def test_phi_is_not_in_payload(self) -> None:
        bundle = _pipeline(devices=(_device(model="patient_id=999 imager"),))
        service, github = _service()
        result = service.notify_advisory(*bundle, now=NOW, change_record_url=ISSUE_URL)
        blob = canonical_event_json(result.event) + github.sink[0]
        self.assertNotIn("patient_id=999", blob)
        self.assertNotIn("999", result.event.device_models[0])

    def test_unacknowledged_critical_escalates(self) -> None:
        bundle = _pipeline()
        service, _github = _service()
        first = service.notify_advisory(*bundle, now=NOW, change_record_url=ISSUE_URL)
        assert first.event is not None
        self.assertIn(first.event.severity, {"CRITICAL", "EMERGENCY"})
        later = NOW + timedelta(hours=2)
        escalations = service.escalate(now=later)
        self.assertEqual(len(escalations), 1)
        assert escalations[0].event is not None
        self.assertIs(escalations[0].event.kind, NotificationKind.ESCALATION)
        service.acknowledge(first.event.event_id, actor="operator@example.invalid", now=later)
        self.assertTrue(
            service.acknowledge(
                first.event.event_id, actor="operator@example.invalid", now=later
            ).acknowledged
        )

    def test_low_priority_rate_limit_batches(self) -> None:
        service, github = _service()
        for index in range(6):
            bundle = _pipeline(
                devices=(
                    _device(
                        device_id=f"SYNTHETIC-LOW-{index}",
                        clinical=ClinicalCriticality.LOW,
                        exposure=NetworkExposure.ISOLATED,
                    ),
                ),
                exploited=TriState.UNKNOWN,
                severity=VendorSeverity.NONE,
                cvss=(
                    CvssRecord(
                        CvssVersion.V3_1, "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 1.0, "nvd"
                    ),
                ),
                remediations=_FIX,
                vendor_advisory_id=f"ADV-LOW-{index}",
            )
            result = service.notify_advisory(
                *bundle, now=NOW + timedelta(minutes=index), change_record_url=ISSUE_URL
            )
            if index < 5:
                self.assertIs(result.event.kind, NotificationKind.ADVISORY)
            else:
                self.assertIs(result.event.kind, NotificationKind.DIGEST)
        self.assertGreaterEqual(len(github.sink), 6)

    def test_webhook_exhausts_retries(self) -> None:
        _advisory_obj, _devices, _apps, _risks, change = _pipeline()
        transport = MappingWebhookTransport({"https://example.invalid/hook": [500, 500, 500]})
        webhook = WebhookChannel("https://example.invalid/hook", transport=transport)
        service, _github = _service(webhook)
        result = service.notify_operational_failure(
            change, now=NOW, change_record_url=ISSUE_URL, reason="deploy adapter failed"
        )
        webhook_delivery = next(item for item in result.deliveries if item.channel == "webhook")
        self.assertIs(webhook_delivery.status, DeliveryStatus.FAILED)
        self.assertEqual(webhook_delivery.attempts, 3)


if __name__ == "__main__":
    unittest.main()
