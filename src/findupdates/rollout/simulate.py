"""Synthetic non-PHI fleet used by staged-rollout tests."""

from __future__ import annotations

from findupdates.rollout.models import MaintenanceWindow, RolloutDevice

ALWAYS_OPEN = MaintenanceWindow(
    timezone="UTC",
    days_of_week=("mon", "tue", "wed", "thu", "fri", "sat", "sun"),
    start_local="00:00",
    duration_minutes=1440,
)

NIGHTLY = MaintenanceWindow(
    timezone="UTC",
    days_of_week=("sun",),
    start_local="02:00",
    duration_minutes=120,
)


def synthetic_device(
    device_id: str,
    *,
    criticality: str = "medium",
    group: str = "ward-a",
    site: str = "hospital-a",
    maintenance: MaintenanceWindow = ALWAYS_OPEN,
    backend: str = "mock-intune",
) -> RolloutDevice:
    """Build one technical device record with no patient identifiers."""
    return RolloutDevice(
        device_id=device_id,
        model="ImagingStation-X200",
        site=site,
        clinical_criticality=criticality,
        deployment_group=group,
        backend=backend,
        maintenance=maintenance,
    )


def synthetic_fleet(
    *,
    lab: int = 2,
    standard: int = 10,
    critical: int = 2,
    maintenance: MaintenanceWindow = ALWAYS_OPEN,
) -> tuple[RolloutDevice, ...]:
    """Return a deterministic simulated fleet for success and failure scenarios."""
    devices = [
        synthetic_device(
            f"lab-{index:02d}", group="lab-ring-0", site="lab", maintenance=maintenance
        )
        for index in range(lab)
    ]
    devices.extend(
        synthetic_device(f"std-{index:02d}", maintenance=maintenance) for index in range(standard)
    )
    devices.extend(
        synthetic_device(
            f"crit-{index:02d}",
            criticality="critical",
            group="icu",
            maintenance=maintenance,
        )
        for index in range(critical)
    )
    return tuple(devices)
