"""Fail-closed rollout errors. None of these are a successful promotion."""


class RolloutError(Exception):
    """Base class for staged-rollout rejections."""


class RolloutDenied(RolloutError):
    """Promotion or execution is forbidden by policy, health or window rules."""


class ConcurrentRollout(RolloutError):
    """A device is already locked to another in-progress rollout."""


class ScopeChanged(RolloutError):
    """Ring membership no longer matches the authorized snapshot."""
