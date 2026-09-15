"""Execute a frozen rollout plan through the deployment adapter."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta

from findupdates.deployment.errors import PartialFailure
from findupdates.deployment.mock import MockDeploymentAdapter
from findupdates.deployment.models import (
    AuthorizationEvidence,
    DeploymentStatus,
    DeploymentTarget,
    OidcCredential,
    PackageIdentity,
    RolloutPolicy,
)
from findupdates.deployment.prepare import prepare
from findupdates.ids import stable_id
from findupdates.rollout.errors import ConcurrentRollout, RolloutDenied, ScopeChanged
from findupdates.rollout.health import assert_promotable, breaches_threshold
from findupdates.rollout.models import (
    STAGE_ORDER,
    HealthSignals,
    PromotionEvent,
    RolloutDevice,
    RolloutPlan,
    RolloutState,
    RolloutStatus,
    StageResult,
    StageSpec,
    StageStatus,
)
from findupdates.rollout.rings import membership_hash
from findupdates.rollout.windows import assert_maintenance


class RolloutController:
    """In-memory staged rollout. Safe to serialize and restore after a workflow restart."""

    def __init__(self, devices: Sequence[RolloutDevice]) -> None:
        self._devices = {item.device_id: item for item in devices}
        self._plans: dict[str, RolloutPlan] = {}
        self._states: dict[str, RolloutState] = {}
        self._locks: dict[str, str] = {}

    def restore(self, plan: RolloutPlan, state: RolloutState) -> RolloutState:
        """Rehydrate an existing rollout so promotion is idempotent after restart."""
        if state.plan_id != plan.plan_id:
            raise RolloutDenied("restored state does not belong to this plan")
        self._plans[plan.plan_id] = plan
        self._states[state.rollout_id] = state
        if state.status in {RolloutStatus.IN_PROGRESS, RolloutStatus.PAUSED}:
            for result in state.stages:
                if result.status in {
                    StageStatus.IN_PROGRESS,
                    StageStatus.OBSERVING,
                    StageStatus.PASSED,
                    StageStatus.PAUSED,
                }:
                    for device_id in plan.stage(result.name).member_device_ids:
                        self._locks[device_id] = state.rollout_id
        return state

    def start(
        self,
        plan: RolloutPlan,
        *,
        actor: str,
        reason: str,
        now: datetime,
        adapter: MockDeploymentAdapter,
        credential: OidcCredential,
        evidence: AuthorizationEvidence,
        package: PackageIdentity,
    ) -> RolloutState:
        """Begin lab (or the first non-empty stage). Repeated calls return the same state."""
        existing = next(
            (item for item in self._states.values() if item.plan_id == plan.plan_id),
            None,
        )
        if existing is not None:
            return existing
        self._plans[plan.plan_id] = plan
        rollout_id = stable_id("rollout", plan.plan_id)
        pending = tuple(
            StageResult(
                name=item.name,
                status=StageStatus.PENDING,
                membership_hash=item.membership_hash,
                deployment_id=None,
                actor=None,
                reason=None,
                started_at=None,
                observation_ends_at=None,
                health=None,
            )
            for item in plan.stages
        )
        state = RolloutState(
            rollout_id=rollout_id,
            plan_id=plan.plan_id,
            status=RolloutStatus.PLANNED,
            current_stage="lab",
            stages=pending,
            promotions=(),
            updated_at=now,
        )
        self._states[rollout_id] = state
        first = _first_populated(plan)
        return self._execute_stage(
            state,
            first,
            actor=actor,
            reason=reason,
            now=now,
            adapter=adapter,
            credential=credential,
            evidence=evidence,
            package=package,
            environment_approved=True,
        )

    def record_health(
        self, rollout_id: str, signals: HealthSignals, *, now: datetime
    ) -> RolloutState:
        """Attach post-update health. Threshold breaches pause promotion."""
        state = self._require(rollout_id)
        plan = self._plans[state.plan_id]
        current = state.stage_result(state.current_stage)
        if current.status not in {StageStatus.IN_PROGRESS, StageStatus.OBSERVING}:
            raise RolloutDenied("health can only be recorded for the active stage")
        spec = plan.stage(state.current_stage)
        status = StageStatus.PAUSED if breaches_threshold(spec, signals) else StageStatus.OBSERVING
        updated = _replace_stage(
            current,
            status=status,
            health=signals,
        )
        rollout_status = (
            RolloutStatus.PAUSED if status is StageStatus.PAUSED else RolloutStatus.IN_PROGRESS
        )
        return self._store(
            RolloutState(
                rollout_id=state.rollout_id,
                plan_id=state.plan_id,
                status=rollout_status,
                current_stage=state.current_stage,
                stages=_swap(state.stages, updated),
                promotions=state.promotions,
                updated_at=now,
            )
        )

    def promote(
        self,
        rollout_id: str,
        *,
        actor: str,
        reason: str,
        now: datetime,
        adapter: MockDeploymentAdapter,
        credential: OidcCredential,
        evidence: AuthorizationEvidence,
        package: PackageIdentity,
        environment_approved: bool,
    ) -> RolloutState:
        """Advance to the next populated ring when observation and health pass."""
        state = self._require(rollout_id)
        if state.status is RolloutStatus.PAUSED:
            raise RolloutDenied("paused rollouts cannot promote")
        if state.status in {RolloutStatus.SUCCEEDED, RolloutStatus.CANCELLED, RolloutStatus.FAILED}:
            raise RolloutDenied(f"rollout is {state.status.value}")
        plan = self._plans[state.plan_id]
        current_spec = plan.stage(state.current_stage)
        current = state.stage_result(state.current_stage)
        if current.status is StageStatus.OBSERVING:
            assert_promotable(current_spec, current, now=now)
            passed = _replace_stage(current, status=StageStatus.PASSED)
            state = self._store(
                RolloutState(
                    rollout_id=state.rollout_id,
                    plan_id=state.plan_id,
                    status=state.status,
                    current_stage=state.current_stage,
                    stages=_swap(state.stages, passed),
                    promotions=state.promotions,
                    updated_at=now,
                )
            )
        elif current.status not in {StageStatus.PASSED, StageStatus.SKIPPED}:
            raise RolloutDenied(
                f"stage {state.current_stage} is {current.status.value} and cannot promote"
            )
        nxt = _next_populated(plan, state.current_stage)
        if nxt is None:
            self._release(state.rollout_id)
            return self._store(
                RolloutState(
                    rollout_id=state.rollout_id,
                    plan_id=state.plan_id,
                    status=RolloutStatus.SUCCEEDED,
                    current_stage=state.current_stage,
                    stages=state.stages,
                    promotions=state.promotions,
                    updated_at=now,
                )
            )
        executed = self._execute_stage(
            state,
            nxt,
            actor=actor,
            reason=reason,
            now=now,
            adapter=adapter,
            credential=credential,
            evidence=evidence,
            package=package,
            environment_approved=environment_approved,
        )
        event = PromotionEvent(
            actor=actor,
            reason=reason,
            from_stage=state.current_stage,
            to_stage=nxt.name,
            membership_hash=nxt.membership_hash,
            at=now,
        )
        return self._store(
            RolloutState(
                rollout_id=executed.rollout_id,
                plan_id=executed.plan_id,
                status=executed.status,
                current_stage=executed.current_stage,
                stages=executed.stages,
                promotions=(*state.promotions, event),
                updated_at=now,
            )
        )

    def pause(
        self,
        rollout_id: str,
        *,
        actor: str,
        reason: str,
        now: datetime,
        adapter: MockDeploymentAdapter,
        credential: OidcCredential,
    ) -> RolloutState:
        """Pause further promotion. Adapter pause is used when the backend supports it."""
        del actor, reason
        state = self._require(rollout_id)
        current = state.stage_result(state.current_stage)
        if current.deployment_id:
            backend = adapter.status(current.deployment_id)
            if backend.status is DeploymentStatus.IN_PROGRESS:
                adapter.pause(current.deployment_id, credential=credential, now=now)
        paused = _replace_stage(current, status=StageStatus.PAUSED)
        return self._store(
            RolloutState(
                rollout_id=state.rollout_id,
                plan_id=state.plan_id,
                status=RolloutStatus.PAUSED,
                current_stage=state.current_stage,
                stages=_swap(state.stages, paused),
                promotions=state.promotions,
                updated_at=now,
            )
        )

    def resume(
        self,
        rollout_id: str,
        *,
        now: datetime,
        adapter: MockDeploymentAdapter,
        credential: OidcCredential,
    ) -> RolloutState:
        """Resume a paused rollout without skipping the observation window."""
        state = self._require(rollout_id)
        if state.status is not RolloutStatus.PAUSED:
            raise RolloutDenied("only paused rollouts can be resumed")
        current = state.stage_result(state.current_stage)
        if current.deployment_id:
            backend = adapter.status(current.deployment_id)
            if backend.status is DeploymentStatus.PAUSED:
                adapter.resume(current.deployment_id, credential=credential, now=now)
        resumed = _replace_stage(current, status=StageStatus.OBSERVING)
        return self._store(
            RolloutState(
                rollout_id=state.rollout_id,
                plan_id=state.plan_id,
                status=RolloutStatus.IN_PROGRESS,
                current_stage=state.current_stage,
                stages=_swap(state.stages, resumed),
                promotions=state.promotions,
                updated_at=now,
            )
        )

    def cancel(
        self,
        rollout_id: str,
        *,
        now: datetime,
        adapter: MockDeploymentAdapter,
        credential: OidcCredential,
    ) -> RolloutState:
        """Stop the rollout. In-progress backend jobs are cancelled when possible."""
        state = self._require(rollout_id)
        current = state.stage_result(state.current_stage)
        if current.deployment_id:
            backend = adapter.status(current.deployment_id)
            if backend.status in {DeploymentStatus.IN_PROGRESS, DeploymentStatus.PAUSED}:
                adapter.cancel(current.deployment_id, credential=credential, now=now)
        cancelled = _replace_stage(current, status=StageStatus.FAILED)
        self._release(state.rollout_id)
        return self._store(
            RolloutState(
                rollout_id=state.rollout_id,
                plan_id=state.plan_id,
                status=RolloutStatus.CANCELLED,
                current_stage=state.current_stage,
                stages=_swap(state.stages, cancelled),
                promotions=state.promotions,
                updated_at=now,
            )
        )

    def state(self, rollout_id: str) -> RolloutState:
        return self._require(rollout_id)

    def _execute_stage(
        self,
        state: RolloutState,
        spec: StageSpec,
        *,
        actor: str,
        reason: str,
        now: datetime,
        adapter: MockDeploymentAdapter,
        credential: OidcCredential,
        evidence: AuthorizationEvidence,
        package: PackageIdentity,
        environment_approved: bool,
    ) -> RolloutState:
        if spec.requires_approval and not environment_approved:
            raise RolloutDenied(f"{spec.name} requires explicit environment approval")
        plan = self._plans[state.plan_id]
        if package.package_id != plan.package_id or package.sha256 != plan.package_sha256:
            raise ScopeChanged("package identity does not match the authorized plan")
        members = tuple(self._devices[item] for item in spec.member_device_ids)
        actual_hash = membership_hash(spec.member_device_ids)
        if actual_hash != spec.membership_hash:
            raise ScopeChanged(f"stage {spec.name} membership changed after authorization")
        self._lock(spec.member_device_ids, state.rollout_id)
        if spec.maintenance_required:
            assert_maintenance(members, now=now, emergency=plan.emergency.authorized)
        targets = tuple(DeploymentTarget(item.device_id, item.backend) for item in members)
        request = prepare(
            package,
            targets,
            RolloutPolicy(spec.environment, spec.name),
            evidence,
        )
        try:
            submitted = adapter.deploy(request, credential=credential, now=now)
            if submitted.status is DeploymentStatus.IN_PROGRESS:
                submitted = adapter.complete(submitted.deployment_id, now=now)
        except PartialFailure as exc:
            failed = StageResult(
                name=spec.name,
                status=StageStatus.FAILED,
                membership_hash=spec.membership_hash,
                deployment_id=None,
                actor=actor,
                reason=str(exc),
                started_at=now,
                observation_ends_at=now,
                health=None,
            )
            return self._store(
                RolloutState(
                    rollout_id=state.rollout_id,
                    plan_id=state.plan_id,
                    status=RolloutStatus.PAUSED,
                    current_stage=spec.name,
                    stages=_swap(state.stages, failed),
                    promotions=state.promotions,
                    updated_at=now,
                )
            )
        observing = StageResult(
            name=spec.name,
            status=StageStatus.OBSERVING,
            membership_hash=spec.membership_hash,
            deployment_id=submitted.deployment_id,
            actor=actor,
            reason=reason,
            started_at=now,
            observation_ends_at=now + timedelta(minutes=spec.observation_window_minutes),
            health=None,
        )
        return self._store(
            RolloutState(
                rollout_id=state.rollout_id,
                plan_id=state.plan_id,
                status=RolloutStatus.IN_PROGRESS,
                current_stage=spec.name,
                stages=_swap(state.stages, observing),
                promotions=state.promotions,
                updated_at=now,
            )
        )

    def _lock(self, device_ids: tuple[str, ...], rollout_id: str) -> None:
        for device_id in device_ids:
            owner = self._locks.get(device_id)
            if owner is not None and owner != rollout_id:
                raise ConcurrentRollout(f"device {device_id} is already in rollout {owner}")
            self._locks[device_id] = rollout_id

    def _release(self, rollout_id: str) -> None:
        for device_id, owner in list(self._locks.items()):
            if owner == rollout_id:
                del self._locks[device_id]

    def _require(self, rollout_id: str) -> RolloutState:
        try:
            return self._states[rollout_id]
        except KeyError as exc:
            raise RolloutDenied(f"unknown rollout {rollout_id}") from exc

    def _store(self, state: RolloutState) -> RolloutState:
        self._states[state.rollout_id] = state
        return state


def _first_populated(plan: RolloutPlan) -> StageSpec:
    for item in plan.stages:
        if item.member_device_ids:
            return item
    raise RolloutDenied("rollout plan has no devices")


def _next_populated(plan: RolloutPlan, current: str) -> StageSpec | None:
    index = STAGE_ORDER.index(current)
    for name in STAGE_ORDER[index + 1 :]:
        spec = plan.stage(name)
        if spec.member_device_ids:
            return spec
    return None


def _replace_stage(
    current: StageResult,
    *,
    status: StageStatus | None = None,
    health: HealthSignals | None = None,
    replace_health: bool = False,
) -> StageResult:
    return StageResult(
        name=current.name,
        status=current.status if status is None else status,
        membership_hash=current.membership_hash,
        deployment_id=current.deployment_id,
        actor=current.actor,
        reason=current.reason,
        started_at=current.started_at,
        observation_ends_at=current.observation_ends_at,
        health=health if replace_health or health is not None else current.health,
    )


def _swap(stages: tuple[StageResult, ...], updated: StageResult) -> tuple[StageResult, ...]:
    return tuple(updated if item.name == updated.name else item for item in stages)
