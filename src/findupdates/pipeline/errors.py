"""Fail-closed errors for the collect-to-change-record handoff."""


class AssessError(Exception):
    """Raised when assess cannot load inputs or complete a fail-closed run."""
