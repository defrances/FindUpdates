"""Per-station update recommendations. Deterministic; not an install authorization."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from findupdates.applicability.models import ApplicabilityResult, ApplicabilityVerdict
from findupdates.inventory.models import DeviceInventory
from findupdates.normalization.models import UpdateAdvisory, Vendor
from findupdates.risk.models import PolicyResult, RiskAssessment

_OFFICIAL_HOSTS = frozenset(
    {
        "msrc.microsoft.com",
        "www.microsoft.com",
        "microsoft.com",
        "www.intel.com",
        "intel.com",
        "www.cisa.gov",
        "cisa.gov",
    }
)

CANDIDATE = "candidate_for_validation"
DO_NOT_INSTALL = "do_not_install"
NOT_IN_SCOPE = "not_in_scope"

_LIST_UNKNOWN_IF = frozenset({"true"})


@dataclass(frozen=True, slots=True)
class StationRecommendation:
    """One advisory assessed against one workstation."""

    device_id: str
    model: str
    device_role: str
    clinical_criticality: str
    network_exposure: str
    deployment_group: str
    os_product: str
    os_build: str | None
    advisory_id: str
    title: str
    vendor: str
    package: str | None
    cve_ids: tuple[str, ...]
    verdict: str
    policy_result: str
    risk_score: int
    severity: str
    official_url: str | None
    explanation: str
    action: str
    listed: bool


def recommend_station(
    advisory: UpdateAdvisory,
    device: DeviceInventory,
    applicability: ApplicabilityResult,
    risk: RiskAssessment,
) -> StationRecommendation:
    """Build a reviewer row. HOLD/BLOCK never become install candidates."""
    action = _action(applicability.verdict, risk.policy_result)
    listed = _listed(applicability, advisory, action)
    package = None
    if advisory.package_ids:
        package = advisory.package_ids[0].value
    return StationRecommendation(
        device_id=device.device_id,
        model=device.model,
        device_role=device.device_role,
        clinical_criticality=device.clinical_criticality.value,
        network_exposure=device.network_exposure.value,
        deployment_group=device.deployment_group,
        os_product=device.os.product,
        os_build=device.os.build,
        advisory_id=advisory.advisory_id,
        title=advisory.title,
        vendor=advisory.vendor.value,
        package=package,
        cve_ids=advisory.cve_ids,
        verdict=applicability.verdict.value,
        policy_result=risk.policy_result.value,
        risk_score=risk.score,
        severity=risk.severity.value,
        official_url=official_advisory_url(advisory),
        explanation=_explanation(advisory, device, applicability, risk, action),
        action=action,
        listed=listed,
    )


def official_advisory_url(advisory: UpdateAdvisory) -> str | None:
    """First allow-listed HTTPS vendor URL. Untrusted text is not used as a URL."""
    urls: list[str] = []
    if advisory.provenance.source_url:
        urls.append(advisory.provenance.source_url)
    urls.extend(advisory.references)
    if advisory.vendor is Vendor.MICROSOFT:
        for cve in advisory.cve_ids:
            if cve.startswith("CVE-"):
                urls.append(f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}")
    for url in urls:
        if _is_official(url):
            return url
    return None


def render_station_report(
    rows: tuple[StationRecommendation, ...],
    *,
    correlation_id: str,
) -> str:
    """Markdown report grouped by station. Job-Summary sized, not a full dump."""
    lines = [
        "# Station update recommendations",
        "",
        "This report is reviewer-facing. It is **not** an authorization to install,",
        "approve, or deploy. HOLD/BLOCK stay HOLD/BLOCK.",
        "",
        f"- correlation=`{correlation_id}`",
        f"- stations=`{len({item.device_id for item in rows})}`",
        f"- pairs=`{len(rows)}`",
        f"- listed=`{sum(1 for item in rows if item.listed)}`",
        "",
    ]
    by_device: dict[str, list[StationRecommendation]] = {}
    for item in rows:
        by_device.setdefault(item.device_id, []).append(item)
    for device_id, items in by_device.items():
        first = items[0]
        lines.extend(
            [
                f"## {device_id} — {first.model}",
                "",
                f"role=`{first.device_role}` group=`{first.deployment_group}` "
                f"os=`{first.os_product}` build=`{first.os_build or 'unknown'}` "
                f"clinical=`{first.clinical_criticality}` "
                f"exposure=`{first.network_exposure}`",
                "",
            ]
        )
        listed = [item for item in items if item.listed]
        hidden = len(items) - len(listed)
        if not listed:
            lines.append("No listed updates for this station.")
            lines.append("")
        for item in listed:
            pkg = item.package or "no-package"
            url = item.official_url or "none (no allow-listed official URL)"
            lines.extend(
                [
                    f"### {item.action} · `{pkg}` · {item.title}",
                    "",
                    f"- advisory=`{item.advisory_id}` vendor=`{item.vendor}` "
                    f"cve={','.join(item.cve_ids) or 'none'}",
                    f"- verdict=`{item.verdict}` policy=`{item.policy_result}` "
                    f"score={item.risk_score} severity=`{item.severity}`",
                    f"- official: {url}",
                    f"- {item.explanation}",
                    "",
                ]
            )
        if hidden:
            lines.append(
                f"{hidden} additional unknown/BLOCK advisories are counted, not listed. "
                "Unknown is not treated as not_affected."
            )
            lines.append("")
    return "\n".join(lines)


def recommendations_to_dict(
    rows: tuple[StationRecommendation, ...], *, correlation_id: str
) -> dict[str, object]:
    """JSON mapping. Token fields are not included."""
    return {
        "correlation_id": correlation_id,
        "item_count": len(rows),
        "listed_count": sum(1 for item in rows if item.listed),
        "items": [
            {
                "device_id": item.device_id,
                "model": item.model,
                "device_role": item.device_role,
                "clinical_criticality": item.clinical_criticality,
                "network_exposure": item.network_exposure,
                "deployment_group": item.deployment_group,
                "os_product": item.os_product,
                "os_build": item.os_build,
                "advisory_id": item.advisory_id,
                "title": item.title,
                "vendor": item.vendor,
                "package": item.package,
                "cve_ids": list(item.cve_ids),
                "verdict": item.verdict,
                "policy_result": item.policy_result,
                "risk_score": item.risk_score,
                "severity": item.severity,
                "official_url": item.official_url,
                "explanation": item.explanation,
                "action": item.action,
                "listed": item.listed,
            }
            for item in rows
            if item.listed
        ],
    }


def _action(verdict: ApplicabilityVerdict, policy: PolicyResult) -> str:
    if verdict is ApplicabilityVerdict.NOT_AFFECTED:
        return NOT_IN_SCOPE
    if policy in {PolicyResult.BLOCK, PolicyResult.HOLD}:
        return DO_NOT_INSTALL
    if verdict is ApplicabilityVerdict.AFFECTED:
        return CANDIDATE
    return DO_NOT_INSTALL


def _listed(
    applicability: ApplicabilityResult,
    advisory: UpdateAdvisory,
    action: str,
) -> bool:
    if action in {CANDIDATE, NOT_IN_SCOPE}:
        return True
    if applicability.verdict is not ApplicabilityVerdict.UNKNOWN:
        return True
    return advisory.known_exploited.value in _LIST_UNKNOWN_IF


def _explanation(
    advisory: UpdateAdvisory,
    device: DeviceInventory,
    applicability: ApplicabilityResult,
    risk: RiskAssessment,
    action: str,
) -> str:
    pkg = advisory.package_ids[0].value if advisory.package_ids else "the vendor package"
    if action == NOT_IN_SCOPE:
        return (
            f"Strong identity shows {device.device_id} is not in the affected set for "
            f"{pkg}. Do not install this update on this station."
        )
    if action == CANDIDATE:
        return (
            f"{device.device_id} is vendor-affected for {pkg}. Deterministic policy is "
            f"{risk.policy_result.value} (score {risk.score}, "
            f"clinical {device.clinical_criticality.value}, "
            f"exposure {device.network_exposure.value}). "
            "Complete lab validation and required approval before any deployment adapter. "
            "This row does not authorize installation."
        )
    if applicability.verdict is ApplicabilityVerdict.UNKNOWN:
        return (
            f"Applicability for {pkg} on {device.device_id} is unknown "
            f"(confidence {applicability.confidence.value}). Unknown is not treated as "
            f"not_affected; policy is {risk.policy_result.value}. Do not install."
        )
    return (
        f"Policy {risk.policy_result.value} forbids promotion of {pkg} on "
        f"{device.device_id}. Do not install."
    )


def _is_official(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname is None:
        return False
    return parsed.hostname.casefold() in _OFFICIAL_HOSTS
