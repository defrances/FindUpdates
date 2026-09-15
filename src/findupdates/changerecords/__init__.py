"""GitHub-facing change records for approval-gated simulated deployment."""

from findupdates.changerecords.build import build_change_record, idempotency_key, labels_for
from findupdates.changerecords.errors import ChangeStoreError
from findupdates.changerecords.github import GitHubChangeStore, github_token, store_from_env
from findupdates.changerecords.models import (
    SCHEMA_VERSION,
    ChangeRecord,
    LifecycleState,
    OverrideEvent,
    PromotionDenied,
)
from findupdates.changerecords.promote import assert_workflow_gate, promote
from findupdates.changerecords.serialize import (
    canonical_record_json,
    issue_body,
    parse_issue_body,
    record_to_dict,
)
from findupdates.changerecords.store import (
    MemoryChangeStore,
    UpsertResult,
    render_github_issue,
    with_github_issue,
)

__all__ = [
    "SCHEMA_VERSION",
    "ChangeRecord",
    "ChangeStoreError",
    "GitHubChangeStore",
    "LifecycleState",
    "MemoryChangeStore",
    "OverrideEvent",
    "PromotionDenied",
    "UpsertResult",
    "assert_workflow_gate",
    "build_change_record",
    "canonical_record_json",
    "github_token",
    "idempotency_key",
    "issue_body",
    "labels_for",
    "parse_issue_body",
    "promote",
    "record_to_dict",
    "render_github_issue",
    "store_from_env",
    "with_github_issue",
]
