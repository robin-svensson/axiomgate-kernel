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

from typing import Any, Dict, List, Optional

from .observation import HOLDS, PARTIAL, UNOBSERVABLE, VIOLATED, ObservationLog

__all__ = [
    "ExecutionError",
    "ExecutionLog",
    "ExecutionRecord",
    "check_execution_invariant",
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

    if not matched and not rolled_back:
        # Nothing executed at all. That is evidence of nothing, and calling it
        # HOLDS is the vacuous truth the four states exist to prevent.
        return {
            "status": PARTIAL,
            "holds": False,
            "detail": "the execution log is empty, so nothing was checked. An empty "
                      "set satisfies 'every execution has an observation' vacuously, "
                      "which is not evidence that the kernel does.",
            "matched": [],
            "unmatched": [],
            "rolled_back": [],
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
