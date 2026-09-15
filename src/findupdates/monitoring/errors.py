"""Fail-closed monitoring errors. Pause is the default; rollback is never implied."""


class MonitoringError(Exception):
    """Base class for post-deploy monitoring rejections."""


class RollbackDenied(MonitoringError):
    """Automated rollback is not permitted for this stage, backend or device class."""


class ResumeDenied(MonitoringError):
    """A paused rollout is not ready to continue promotion."""


class PromotionBlocked(MonitoringError):
    """The stage is not HEALTHY or the observation window is still open."""
