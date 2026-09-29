"""The third log: what actually ran, so I5 can be answered rather than asserted.

`docs/TRACEABILITY.md` marked I5 `MODEL-ONLY` -- *every execution has a matching
observation* -- for the same single reason I1, I4 and I6 carried before
``observation.py`` was written. The invariant relates two logs, and the kernel
kept only one of them. Execution here is the redemption of a ``ReservedGrant``,
and ``ReservedGrantStore.consume_if_valid`` is the only way to redeem one.

**Why the ``consumed`` flag on the grant is not this log.** ``unconsume`` exists:
a redemption is rolled back when downstream audit logging fails, and the flag
goes back to ``False``. A log that appended on consume and stopped there would
carry an execution that never happened and keep carrying it after the rollback.
Deleting the record instead would lose that it was ever attempted, which is what
an auditor most wants to see. So a record is written once and *marked*, and the
check reads three states out of it: executed, rolled back, never happened.

Like ``ObservationLog``, this proves ordering within one process. It has no MAC
chain and is never written to disk -- that is ``AuditLog``'s job, and this is not
a replacement for it. See ``docs/ROADMAP.md`` R5.
"""

import asyncio
import inspect
import re
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from .canonical import canonical_bytes
from .crypto import sha256_hex
from .domain import Verdict
from .observation import HOLDS, PARTIAL, UNOBSERVABLE, VIOLATED, ObservationLog

__all__ = [
    "ExecutionError",
    "ExecutionLog",
    "ExecutionRecord",
    "check_execution_invariant",
    "EffectStatus",
    "EffectExecutionResult",
    "EffectExecutionContext",
    "EffectOutcome",
    "EffectExecutorRegistry",
    "KernelEffectRunner",
]


class ExecutionError(Exception):
    """Raised on an attempt to rewrite the record of what ran."""


class ExecutionRecord:
    """One redemption. Written once; only ``rolled_back`` ever changes, and only
    through :meth:`ExecutionLog.mark_rolled_back`.

    Not a frozen dataclass on purpose, and the reason is the same one
    ``ObservationRecord`` carries: ``FrozenInstanceError`` *is* an
    ``AttributeError``, and surrounding code swallows those out of habit. A
    distinct exception type cannot be caught by accident.
    """

    __slots__ = ("seq", "request_id", "principal_id", "escalation_id", "rolled_back", "_sealed")

    def __init__(self, seq: int, request_id: Any, principal_id: Any, escalation_id: Any) -> None:
        object.__setattr__(self, "seq", seq)
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "principal_id", principal_id)
        object.__setattr__(self, "escalation_id", escalation_id)
        object.__setattr__(self, "rolled_back", False)
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: Any) -> None:
        raise ExecutionError(
            f"the execution log is append-only; {name!r} cannot be reassigned. "
            "A rollback is recorded with ExecutionLog.mark_rolled_back(seq)."
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        state = "rolled back" if self.rolled_back else "executed"
        return f"<ExecutionRecord seq={self.seq} request={self.request_id!r} {state}>"


class ExecutionLog:
    """Append-only record of grant redemptions.

    Opt-in, like the observation log and the two protections in R1/R2: a
    ``ReservedGrantStore`` built without one behaves exactly as it did, and
    :func:`check_execution_invariant` then answers ``UNOBSERVABLE`` rather than
    passing over an empty set.
    """

    def __init__(self) -> None:
        self._entries: List[ExecutionRecord] = []

    def record(self, *, request_id: Any, principal_id: Any, escalation_id: Any) -> ExecutionRecord:
        """Append one redemption and hand the record back.

        ``seq`` starts at 1, not 0: ``if seq:`` on a legitimate zero reads as
        absence, and the caller storing this number has no way to tell the
        difference afterwards.
        """
        rec = ExecutionRecord(len(self._entries) + 1, request_id, principal_id, escalation_id)
        self._entries.append(rec)
        return rec

    def mark_rolled_back(self, seq: int) -> None:
        """Record that the redemption at ``seq`` was undone.

        Raises:
            ExecutionError: no record carries that sequence number. Silently
                ignoring it would let a rollback be lost to a typo, and the log
                would then demand an observation for something that never ran.
        """
        for rec in self._entries:
            if rec.seq == seq:
                object.__setattr__(rec, "rolled_back", True)
                return
        raise ExecutionError(f"no execution record with seq={seq!r} to roll back")

    def for_request(self, request_id: Any) -> Optional[ExecutionRecord]:
        """The most recent redemption for a request, or ``None``.

        Most recent rather than first: a rolled-back redemption can legitimately
        be followed by a successful one for the same request.
        """
        for rec in reversed(self._entries):
            if rec.request_id == request_id:
                return rec
        return None

    def entries(self) -> List[ExecutionRecord]:
        """A copy. Handing back the live list lets a caller append to the record
        of what ran."""
        return list(self._entries)


def check_execution_invariant(
    executions: Optional[ExecutionLog],
    observations: Optional[ObservationLog],
) -> Dict[str, Any]:
    """Check I5 -- every execution has an identity-matching observation.

    Pass ``None`` for ``executions`` when the store was built without a log: the
    answer is ``UNOBSERVABLE``, which is honest, and not a pass.

    Returns ``{"status": ..., "holds": bool, ...}``. ``holds`` is true only for
    ``HOLDS``; ``PARTIAL`` does not count, because the model's statement is what
    is being checked and it is not satisfied by "almost every".
    """
    if executions is None:
        return {
            "status": UNOBSERVABLE,
            "holds": False,
            "detail": "the grant store was built without an execution log, so there "
                      "is no evidence either way. Pass executions=ExecutionLog() to "
                      "ReservedGrantStore(...).",
            "matched": [],
            "unmatched": [],
            "rolled_back": [],
        }

    if observations is None:
        return {
            "status": UNOBSERVABLE,
            "holds": False,
            "detail": "there is an execution log but no observation log, so the "
                      "invariant relates one log to nothing. Pass "
                      "observations=ObservationLog() to Mediator(...).",
            "matched": [],
            "unmatched": [],
            "rolled_back": [],
        }

    by_request = {}
    for obs in observations.entries():
        by_request[obs.request_id] = obs

    matched, unmatched, rolled_back = [], [], []
    for rec in executions.entries():
        if rec.rolled_back:
            # It did not execute. Demanding an observation for it would report
            # VIOLATED on a kernel that behaved correctly, and a check that cries
            # wolf on correct behaviour is a check somebody turns off.
            rolled_back.append(rec.seq)
            continue
        obs = by_request.get(rec.request_id)
        if obs is None:
            unmatched.append({"seq": rec.seq, "request_id": rec.request_id,
                              "why": "no observation names this request"})
        elif obs.principal_id != rec.principal_id:
            # Matching on request_id alone would call this a pass -- which is the
            # I6 failure, one log further along.
            unmatched.append({"seq": rec.seq, "request_id": rec.request_id,
                              "why": f"observation names {obs.principal_id!r}, "
                                     f"execution names {rec.principal_id!r}"})
        else:
            matched.append(rec.seq)

    if unmatched:
        return {
            "status": VIOLATED,
            "holds": False,
            "detail": f"{len(unmatched)} execution(s) have no identity-matching "
                      "observation. Something ran that the kernel has no record of seeing.",
            "matched": matched,
            "unmatched": unmatched,
            "rolled_back": rolled_back,
        }

    if not matched:
        # No execution stood. That is evidence of nothing, and calling it HOLDS is
        # the vacuous truth the four states exist to prevent. A log of nothing but
        # rollbacks is the same fact wearing a busier shape: zero confirmed
        # executions, with entries present to make the report look substantiated.
        if rolled_back:
            detail = (f"{len(rolled_back)} execution(s) were recorded and all of them "
                      "were rolled back, so no execution stands to have been observed. "
                      "The invariant was not contradicted and it was not confirmed "
                      "either -- a busy-looking log is not evidence.")
        else:
            detail = ("the execution log is empty, so nothing was checked. An empty "
                      "set satisfies 'every execution has an observation' vacuously, "
                      "which is not evidence that the kernel does.")
        return {
            "status": PARTIAL,
            "holds": False,
            "detail": detail,
            "matched": [],
            "unmatched": [],
            "rolled_back": rolled_back,
        }

    return {
        "status": HOLDS,
        "holds": True,
        "detail": f"{len(matched)} execution(s) matched an identity-bound observation; "
                  f"{len(rolled_back)} rolled back and correctly require none.",
        "matched": matched,
        "unmatched": [],
        "rolled_back": rolled_back,
    }


class EffectStatus(str, Enum):
    """Outcome states for one Kernel-controlled external effect attempt."""

    SUCCESS = "SUCCESS"
    DENIED = "DENIED"
    FAILED_BEFORE_EFFECT = "FAILED_BEFORE_EFFECT"
    EFFECT_FAILED = "EFFECT_FAILED"
    INDETERMINATE_AFTER_EFFECT = "INDETERMINATE_AFTER_EFFECT"


@dataclass(frozen=True)
class EffectExecutionResult:
    """Normalized result returned only by a registered executor."""

    status: EffectStatus
    value: Any = None
    provider_reference: Optional[str] = None
    idempotency_reference: Optional[str] = None
    output_digest: Optional[str] = None
    reason_code: Optional[str] = None

    def __post_init__(self) -> None:
        if self.output_digest is not None and not re.fullmatch(r"[0-9a-f]{64}", self.output_digest):
            raise ValueError("effect output digest must be a lowercase SHA-256 value")

    @classmethod
    def success(
        cls,
        *,
        value: Any = None,
        provider_reference: Optional[str] = None,
        idempotency_reference: Optional[str] = None,
        output_digest: Optional[str] = None,
    ) -> "EffectExecutionResult":
        return cls(
            EffectStatus.SUCCESS,
            value=value,
            provider_reference=provider_reference,
            idempotency_reference=idempotency_reference,
            output_digest=output_digest,
        )

    @classmethod
    def failed_before_effect(cls, reason_code: str) -> "EffectExecutionResult":
        return cls(EffectStatus.FAILED_BEFORE_EFFECT, reason_code=reason_code)

    @classmethod
    def effect_failed(
        cls,
        reason_code: str,
        *,
        provider_reference: Optional[str] = None,
        idempotency_reference: Optional[str] = None,
    ) -> "EffectExecutionResult":
        return cls(
            EffectStatus.EFFECT_FAILED,
            provider_reference=provider_reference,
            idempotency_reference=idempotency_reference,
            reason_code=reason_code,
        )

    @classmethod
    def indeterminate(
        cls,
        reason_code: str,
        *,
        provider_reference: Optional[str] = None,
        idempotency_reference: Optional[str] = None,
        output_digest: Optional[str] = None,
    ) -> "EffectExecutionResult":
        return cls(
            EffectStatus.INDETERMINATE_AFTER_EFFECT,
            provider_reference=provider_reference,
            idempotency_reference=idempotency_reference,
            output_digest=output_digest,
            reason_code=reason_code,
        )


_EFFECT_CONTEXT_SEAL = object()


class EffectExecutionContext:
    """Private per-call marker for the point where an effect may begin."""

    __slots__ = ("grant_id", "executor_id", "request_id", "_started", "_lock", "_seal")

    def __init__(
        self,
        grant_id: str,
        executor_id: str,
        request_id: str,
        *,
        _seal: Any = None,
    ) -> None:
        if _seal is not _EFFECT_CONTEXT_SEAL:
            raise ExecutionError("effect context must be issued by KernelEffectRunner")
        self.grant_id = grant_id
        self.executor_id = executor_id
        self.request_id = request_id
        self._started = False
        self._lock = threading.Lock()
        self._seal = _seal

    def require_executor(self, executor_id: str) -> None:
        """Validate that this context came from the runner for this executor."""
        if (type(self) is not EffectExecutionContext
                or self._seal is not _EFFECT_CONTEXT_SEAL
                or self.executor_id != executor_id):
            raise ExecutionError("effect context does not authorize this executor")

    def begin_effect(self) -> None:
        """Mark immediately before a provider call or other governed write."""
        with self._lock:
            if self._started:
                raise ExecutionError("effect boundary was already entered")
            self._started = True

    @property
    def effect_started(self) -> bool:
        return self._started


@dataclass(frozen=True)
class EffectOutcome:
    """Audited result of one attempted effect invocation."""

    status: EffectStatus
    request_id: Optional[str]
    grant_id: Optional[str] = None
    executor_id: Optional[str] = None
    authorization_audit_hash: Optional[str] = None
    grant_audit_hash: Optional[str] = None
    effect_audit_hash: Optional[str] = None
    provider_reference: Optional[str] = None
    idempotency_reference: Optional[str] = None
    output_digest: Optional[str] = None
    value: Any = None
    reason_code: Optional[str] = None


class EffectExecutorRegistry:
    """Closed registry of stable executor identities, frozen before use."""

    _ID = re.compile(r"[a-z][a-z0-9_.-]{0,95}\Z")

    def __init__(self) -> None:
        self._executors: Dict[str, Callable[..., EffectExecutionResult]] = {}
        self._frozen = False
        self._lock = threading.Lock()

    def register(self, executor_id: str, executor: Callable[..., EffectExecutionResult]) -> None:
        """Register a trusted implementation during startup, before freeze."""
        if not isinstance(executor_id, str) or not self._ID.fullmatch(executor_id):
            raise ValueError("invalid executor id")
        if not callable(executor):
            raise TypeError("executor must be callable")
        with self._lock:
            if self._frozen:
                raise ValueError("executor registry is frozen")
            if executor_id in self._executors:
                raise ValueError("duplicate executor id")
            self._executors[executor_id] = executor

    def freeze(self) -> None:
        """Close registration before an execution runner is constructed."""
        with self._lock:
            if not self._executors:
                raise ValueError("executor registry cannot be empty")
            self._frozen = True

    @property
    def frozen(self) -> bool:
        return self._frozen

    @property
    def executor_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._executors))

    def resolve(self, executor_id: str) -> Callable[..., EffectExecutionResult]:
        with self._lock:
            if not self._frozen:
                raise ValueError("executor registry must be frozen before use")
            try:
                return self._executors[executor_id]
            except KeyError as exc:
                raise ValueError("unknown executor id") from exc


@dataclass(frozen=True)
class _PreparedEffect:
    request: Mapping[str, Any]
    binding: Any
    arguments_bytes: bytes
    payload: bytes
    executor: Callable[..., EffectExecutionResult]
    grant: Any
    authorization_audit_hash: str
    grant_audit_hash: str


class KernelEffectRunner:
    """Authorize, consume and invoke only a registered production executor.

    The caller supplies data and a stable executor ID, never executable code.
    The request is authenticated by the supplied ``Mediator`` and its PERMIT
    audit record is the root of every later effect record in the causal chain.
    """

    def __init__(self, mediator, audit, executors: EffectExecutorRegistry, grant_store) -> None:
        if not executors.frozen:
            raise ValueError("executor registry must be frozen before runner startup")
        if getattr(mediator, "_audit", None) is not audit:
            raise ValueError("runner and mediator must share one audit log")
        self._mediator = mediator
        self._audit = audit
        self._executors = executors
        self._grant_store = grant_store

    def execute(
        self,
        authorization_request: Mapping[str, Any],
        *,
        executor_id: str,
        effect_category: str,
        resource: str,
        operation: str,
        arguments: Mapping[str, Any],
        payload: bytes,
    ) -> EffectOutcome:
        """Execute one synchronous effect through a signed Kernel authorization."""
        prepared_or_denied = self._prepare(
            authorization_request, executor_id, effect_category, resource,
            operation, arguments, payload,
        )
        if isinstance(prepared_or_denied, EffectOutcome):
            return prepared_or_denied
        prepared = prepared_or_denied
        context = EffectExecutionContext(
            prepared.grant.grant_id,
            executor_id,
            prepared.binding.request_id,
            _seal=_EFFECT_CONTEXT_SEAL,
        )
        try:
            result = prepared.executor(context, prepared.arguments_bytes, prepared.payload)
            if inspect.isawaitable(result):
                close = getattr(result, "close", None)
                if callable(close):
                    close()
                result = EffectExecutionResult.failed_before_effect("async_executor_requires_async_call")
        except Exception as exc:
            result = EffectExecutionResult(
                EffectStatus.INDETERMINATE_AFTER_EFFECT if context.effect_started
                else EffectStatus.FAILED_BEFORE_EFFECT,
                reason_code=type(exc).__name__,
            )
        return self._finish(prepared, context, result)

    async def execute_async(
        self,
        authorization_request: Mapping[str, Any],
        *,
        executor_id: str,
        effect_category: str,
        resource: str,
        operation: str,
        arguments: Mapping[str, Any],
        payload: bytes,
    ) -> EffectOutcome:
        """Execute one async effect through the same single-use grant boundary."""
        prepared_or_denied = self._prepare(
            authorization_request, executor_id, effect_category, resource,
            operation, arguments, payload,
        )
        if isinstance(prepared_or_denied, EffectOutcome):
            return prepared_or_denied
        prepared = prepared_or_denied
        context = EffectExecutionContext(
            prepared.grant.grant_id,
            executor_id,
            prepared.binding.request_id,
            _seal=_EFFECT_CONTEXT_SEAL,
        )
        try:
            result = prepared.executor(context, prepared.arguments_bytes, prepared.payload)
            if inspect.isawaitable(result):
                result = await result
        except asyncio.CancelledError:
            # Once an async provider call crossed the boundary, cancellation
            # cannot prove whether the provider acted. Consume the grant and
            # durably report the attempt as indeterminate before returning.
            result = EffectExecutionResult.indeterminate("executor_cancelled")
        except Exception as exc:
            result = EffectExecutionResult(
                EffectStatus.INDETERMINATE_AFTER_EFFECT if context.effect_started
                else EffectStatus.FAILED_BEFORE_EFFECT,
                reason_code=type(exc).__name__,
            )
        return self._finish(prepared, context, result)

    def _prepare(
        self,
        authorization_request: Mapping[str, Any],
        executor_id: str,
        effect_category: str,
        resource: str,
        operation: str,
        arguments: Mapping[str, Any],
        payload: bytes,
    ):
        """Match signed intent to immutable inputs, authorize, audit and consume."""
        request_id = None
        try:
            if not isinstance(authorization_request, Mapping):
                raise ValueError("authorization request is not a mapping")
            request = dict(authorization_request)
            request_id = request.get("request_id")
            if not isinstance(payload, bytes):
                raise ValueError("effect payload must be immutable bytes")
            if not isinstance(arguments, Mapping):
                raise ValueError("effect arguments must be a mapping")
            arguments_bytes = canonical_bytes(dict(arguments))
            arguments_digest = sha256_hex(arguments_bytes)
            payload_digest = sha256_hex(payload)
            executor = self._executors.resolve(executor_id)
            expected = {
                "executor_id": executor_id,
                "effect_category": effect_category,
                "resource": resource,
                "operation": operation,
                "arguments_sha256": arguments_digest,
                "payload_sha256": payload_digest,
                "tool_name": f"production_effect.{effect_category}",
                "action_type": "EXECUTE",
            }
            if any(request.get(key) != value for key, value in expected.items()):
                raise ValueError("signed effect request does not match invocation")
            principal_id = request.get("principal_id")
            if not isinstance(principal_id, str) or not principal_id:
                raise ValueError("effect request principal is missing")
            if not isinstance(request_id, str) or not request_id:
                raise ValueError("effect request id is missing")
        except Exception as exc:
            return self._denied(request_id, executor_id, "invocation_binding_mismatch")

        try:
            decision = self._mediator.evaluate(request)
        except Exception:
            return self._denied(request_id, executor_id, "mediator_unavailable")
        if (decision.verdict is not Verdict.PERMIT or not decision.audit_hash
                or decision.bound_principal != principal_id):
            return EffectOutcome(
                EffectStatus.DENIED,
                request_id=request_id,
                executor_id=executor_id,
                authorization_audit_hash=decision.audit_hash,
                reason_code="kernel_denied_or_unrecorded",
            )

        # Import locally: grant.py already imports ExecutionLog from this module.
        from .grant import EffectGrantBinding

        binding = EffectGrantBinding(
            request_id=request_id,
            principal_id=principal_id,
            action=str(request["action_type"]),
            tool=str(request["tool_name"]),
            effect_category=effect_category,
            resource=resource,
            operation=operation,
            arguments_digest=arguments_digest,
            payload_digest=payload_digest,
            executor_id=executor_id,
        )
        try:
            grant = self._grant_store.issue(decision, binding)
            grant_audit_hash = self._audit.append({
                "event_type": "effect.grant_issued",
                "request_id": request_id,
                "principal_id": principal_id,
                "action": binding.action,
                "tool": binding.tool,
                "effect_category": effect_category,
                "resource": resource,
                "operation": operation,
                "arguments_sha256": arguments_digest,
                "payload_sha256": payload_digest,
                "executor_id": executor_id,
                "grant_id": grant.grant_id,
                "grant_issued_at": grant.issued_at,
                "grant_expires_at": grant.expires_at,
                "decision_record_entry": decision.audit_hash,
            })
            self._grant_store.consume(grant.grant_id, binding)
        except Exception:
            return EffectOutcome(
                EffectStatus.DENIED,
                request_id=request_id,
                executor_id=executor_id,
                authorization_audit_hash=decision.audit_hash,
                reason_code="grant_or_pre_effect_audit_failed",
            )

        return _PreparedEffect(
            request=request,
            binding=binding,
            arguments_bytes=arguments_bytes,
            payload=payload,
            executor=executor,
            grant=grant,
            authorization_audit_hash=decision.audit_hash,
            grant_audit_hash=grant_audit_hash,
        )

    def _finish(
        self,
        prepared: _PreparedEffect,
        context: EffectExecutionContext,
        result: Any,
    ) -> EffectOutcome:
        """Normalize and durably correlate the executor outcome."""
        if not isinstance(result, EffectExecutionResult):
            normalized = EffectExecutionResult(
                EffectStatus.INDETERMINATE_AFTER_EFFECT if context.effect_started
                else EffectStatus.FAILED_BEFORE_EFFECT,
                reason_code="invalid_executor_result",
            )
        elif result.status is EffectStatus.DENIED:
            normalized = EffectExecutionResult(
                EffectStatus.INDETERMINATE_AFTER_EFFECT if context.effect_started
                else EffectStatus.FAILED_BEFORE_EFFECT,
                reason_code="executor_cannot_issue_denial",
            )
        elif result.status is EffectStatus.FAILED_BEFORE_EFFECT and context.effect_started:
            normalized = EffectExecutionResult.indeterminate("executor_outcome_conflict")
        elif (result.status in (EffectStatus.SUCCESS, EffectStatus.EFFECT_FAILED,
                                EffectStatus.INDETERMINATE_AFTER_EFFECT)
              and not context.effect_started):
            normalized = EffectExecutionResult.failed_before_effect("executor_effect_not_started")
        else:
            normalized = result

        record = {
            "event_type": "effect.completed",
            "request_id": prepared.binding.request_id,
            "principal_id": prepared.binding.principal_id,
            "action": prepared.binding.action,
            "tool": prepared.binding.tool,
            "effect_category": prepared.binding.effect_category,
            "resource": prepared.binding.resource,
            "operation": prepared.binding.operation,
            "arguments_sha256": prepared.binding.arguments_digest,
            "payload_sha256": prepared.binding.payload_digest,
            "executor_id": prepared.binding.executor_id,
            "grant_id": prepared.grant.grant_id,
            "decision_record_entry": prepared.authorization_audit_hash,
            "grant_record_entry": prepared.grant_audit_hash,
            "outcome": normalized.status.value,
            "effect_started": context.effect_started,
            "provider_reference": normalized.provider_reference,
            "idempotency_reference": normalized.idempotency_reference,
            "output_sha256": normalized.output_digest,
            "reason_code": normalized.reason_code,
        }
        try:
            effect_audit_hash = self._audit.append(record)
        except Exception:
            if context.effect_started:
                normalized = EffectExecutionResult.indeterminate("post_effect_audit_failed",
                                                                 provider_reference=normalized.provider_reference,
                                                                 idempotency_reference=normalized.idempotency_reference,
                                                                 output_digest=normalized.output_digest)
            return EffectOutcome(
                normalized.status,
                request_id=prepared.binding.request_id,
                grant_id=prepared.grant.grant_id,
                executor_id=prepared.binding.executor_id,
                authorization_audit_hash=prepared.authorization_audit_hash,
                grant_audit_hash=prepared.grant_audit_hash,
                provider_reference=normalized.provider_reference,
                idempotency_reference=normalized.idempotency_reference,
                output_digest=normalized.output_digest,
                value=normalized.value if normalized.status is EffectStatus.SUCCESS else None,
                reason_code=normalized.reason_code or "post_effect_audit_failed",
            )
        return EffectOutcome(
            normalized.status,
            request_id=prepared.binding.request_id,
            grant_id=prepared.grant.grant_id,
            executor_id=prepared.binding.executor_id,
            authorization_audit_hash=prepared.authorization_audit_hash,
            grant_audit_hash=prepared.grant_audit_hash,
            effect_audit_hash=effect_audit_hash,
            provider_reference=normalized.provider_reference,
            idempotency_reference=normalized.idempotency_reference,
            output_digest=normalized.output_digest,
            value=normalized.value if normalized.status is EffectStatus.SUCCESS else None,
            reason_code=normalized.reason_code,
        )

    def _denied(self, request_id: Any, executor_id: Any, reason_code: str) -> EffectOutcome:
        """Record a bounded denial; audit failure can never authorize execution."""
        try:
            self._audit.append({
                "event_type": "effect.denied",
                "request_id": request_id if isinstance(request_id, str) else None,
                "executor_id": executor_id if isinstance(executor_id, str) else None,
                "reason_code": reason_code,
            })
        except Exception:
            pass
        return EffectOutcome(
            EffectStatus.DENIED,
            request_id=request_id if isinstance(request_id, str) else None,
            executor_id=executor_id if isinstance(executor_id, str) else None,
            reason_code=reason_code,
        )
