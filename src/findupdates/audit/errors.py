"""Fail-closed audit errors. History is never rewritten in place."""


class AuditError(Exception):
    """Base class for evidence-store failures."""


class ImmutableViolation(AuditError):
    """Raised when a caller tries to overwrite an existing evidence record."""


class IntegrityFailure(AuditError):
    """Raised when a hash chain or attachment digest does not verify."""
