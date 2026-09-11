"""The observation log, and the three invariants that could not be checked without it.

``docs/TRACEABILITY.md`` marks I1, I4 and I6 MODEL-ONLY for one reason shared
between them: each is a statement relating the model's ``obsLog`` to its
``enforceLog``, and the kernel kept only the second. Every decision reaches the
audit chain. Nothing recorded the moment the kernel *observed* a request --
authenticated it and bound it to an identity -- so an audit entry had no earlier
record to be checked against.

The kernel already did the right thing. ``Mediator._gated`` authenticates before
it dispatches, so an identity-bound observation does precede every enforcement
that follows one. That was the problem: it was a property of the source text,
provable only by reading ``_gated``, gone the moment someone reorders it, and
worth nothing to an operator who cannot see the source. An invariant that holds
by inspection is not enforced; it is merely true for now.

What this module adds is the missing log and a check over the pair:

``ObservationLog``
    Append-only, monotonic. One record per authenticated request, taken before
    the decision is dispatched.

``check_invariants``
    Reads an observation log and an audit chain and reports I1, I4 and I6 with
    a status each.

**The statuses are four, not two, and the fourth one matters most.** A kernel
built without an observation log reports ``UNOBSERVABLE`` -- never ``HOLDS``.
There is no evidence either way, and unconfirmed is not true. A check that
cannot say "I don't know" will eventually say "yes" when it means it.

**What is honestly reported rather than hidden.** Some enforcements have no
observation and never will: the kernel denies an unavailable mediator, an
uncanonicalizable request, and a failed authentication *before* any identity
exists. I1 as the model states it does not hold over those. They are counted and
their rules are named, and the status is ``PARTIAL``. Excluding them would raise
the score and destroy the meaning -- the excluded case is exactly the one a
reader would want to ask about.

**The limit of I4.** The check confirms that the two logs are *consistent with*
observation preceding enforcement: the sequence numbers carried into the audit
chain are strictly increasing in chain order, so an interleaving that broke the
ordering would show. It does not derive the ordering from first principles --
nothing reading two logs after the fact can. That is a real narrowing against
the model's statement, and ``docs/TRACEABILITY.md`` says PARTIAL for that reason.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

__all__ = ["ObservationError", "ObservationRecord", "ObservationLog", "check_invariants"]


class ObservationError(Exception):
    """An observation record was written to after it was made."""


class ObservationRecord:
    """One observation: an identity, bound to a request, at a point in a sequence.

    Not a frozen dataclass. ``FrozenInstanceError`` is an ``AttributeError``, and
    an ``AttributeError`` is the kind of exception surrounding code swallows by
    habit. Rewriting the log that establishes ordering deserves an exception
    nobody catches by accident.
    """

    __slots__ = ("seq", "principal_id", "request_id", "payload_hash", "timestamp", "_sealed")

    def __init__(self, seq: int, principal_id: str, request_id: Optional[str],
                 payload_hash: Optional[str], timestamp: str) -> None:
        object.__setattr__(self, "seq", seq)
        object.__setattr__(self, "principal_id", principal_id)
        object.__setattr__(self, "request_id", request_id)
        object.__setattr__(self, "payload_hash", payload_hash)
        object.__setattr__(self, "timestamp", timestamp)
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: Any) -> None:
        raise ObservationError(
            f"observation records are append-only; {name!r} cannot be changed. "
            "A log whose ordering can be rewritten proves nothing about ordering, "
            "because the ordering could have been written afterwards."
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"ObservationRecord(seq={self.seq}, principal_id={self.principal_id!r})"


class ObservationLog:
    """Append-only record of what the kernel observed, in the order it observed it.

    In memory. The audit chain is the durable, tamper-evident record; this is the
    ordering evidence that goes alongside it for the lifetime of a process. Making
    it durable is a separate question with its own answer, and pretending it is
    already answered would be the more expensive mistake.
    """

    def __init__(self) -> None:
        self._records: List[ObservationRecord] = []
        self._by_request: Dict[str, ObservationRecord] = {}

    def record(self, principal_id: str, request_id: Optional[str],
               payload_hash: Optional[str]) -> ObservationRecord:
        """Append one observation and return it. The sequence starts at 1.

        Starting at 1 rather than 0 so that a missing sequence number is never
        confused with the first one: a missing value is written as None, and
        ``if seq:`` on a legitimate zero would read as absence.
        """
        rec = ObservationRecord(
            seq=len(self._records) + 1,
            principal_id=principal_id,
            request_id=request_id,
            payload_hash=payload_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        self._records.append(rec)
        if request_id is not None:
            self._by_request[request_id] = rec
        return rec

    def entries(self) -> List[ObservationRecord]:
        """A copy. Handing out the live list would let a caller append to the log
        through the reader, which is the same hole by a slower route."""
        return list(self._records)

    def for_request(self, request_id: Optional[str]) -> Optional[ObservationRecord]:
        if request_id is None:
            return None
        return self._by_request.get(request_id)

    def __len__(self) -> int:
        return len(self._records)


# Status vocabulary. Four, because two would force a lie in two of the cases.
HOLDS = "HOLDS"
PARTIAL = "PARTIAL"
VIOLATED = "VIOLATED"
UNOBSERVABLE = "UNOBSERVABLE"


def check_invariants(observations: Optional[ObservationLog],
                     audit_entries: List[dict]) -> Dict[str, Any]:
    """Check I1, I4 and I6 over an observation log and an audit chain.

    Pass ``None`` for a kernel that was built without an observation log: the
    result is ``UNOBSERVABLE`` throughout, which is the honest answer and not a
    failure of the kernel.

    Returns a dict keyed ``I1``, ``I4``, ``I6``, each ``{"status": ..., ...}``,
    plus ``holds`` -- true only when all three are ``HOLDS``. ``PARTIAL`` does
    not count as holding: the model's statement is what is being checked, and it
    is not satisfied by "almost every".
    """
    if observations is None:
        unobservable = {
            "status": UNOBSERVABLE,
            "detail": "the kernel was built without an observation log, so there "
                      "is no evidence either way. Pass observations=ObservationLog() "
                      "to Mediator(...).",
        }
        return {
            "I1": dict(unobservable),
            "I4": dict(unobservable),
            "I6": dict(unobservable),
            "holds": False,
        }

    entries = list(audit_entries)
    by_seq = {r.seq: r for r in observations.entries()}

    # --- I1: every enforcement has an identity-bound observation ---
    observed, unobserved = [], []
    dangling = []
    for entry in entries:
        seq = entry.get("observation_seq")
        if seq is None:
            unobserved.append(entry)
        elif seq not in by_seq:
            # An audit entry naming an observation the log does not have means
            # the two records disagree about what happened. That is worse than
            # a missing observation, not better, so it is never PARTIAL.
            dangling.append(entry)
        else:
            observed.append((entry, by_seq[seq]))

    if dangling:
        i1 = {
            "status": VIOLATED,
            "detail": f"{len(dangling)} audit entries name an observation that is "
                      "not in the log",
        }
    elif not entries:
        i1 = {"status": UNOBSERVABLE,
              "detail": "the audit chain is empty; there is nothing to check"}
    elif not observed:
        # Vacuous truth is the failure mode a check like this dies of: an empty
        # pytest parametrisation reported green for exactly this reason.
        i1 = {"status": VIOLATED,
              "detail": f"none of the {len(entries)} audit entries has an observation"}
    elif unobserved:
        i1 = {
            "status": PARTIAL,
            "detail": "some enforcements were reached before an identity existed, "
                      "so they have no observation and I1 does not hold over them",
        }
    else:
        i1 = {"status": HOLDS, "detail": f"all {len(entries)} enforcements are observed"}

    rules = []
    for entry in unobserved:
        rules.extend(entry.get("applied_rules") or [])
    i1["unobserved_enforcements"] = len(unobserved)
    i1["unobserved_rules"] = sorted(set(rules))
    i1["observed_enforcements"] = len(observed)

    # --- I4: observation precedes enforcement ---
    seqs = [entry.get("observation_seq") for entry, _ in observed]
    out_of_order = [
        (a, b) for a, b in zip(seqs, seqs[1:]) if b <= a
    ]
    if not observed:
        i4 = {"status": i1["status"] if i1["status"] != PARTIAL else VIOLATED,
              "detail": "no observed enforcement to order"}
    elif out_of_order:
        i4 = {"status": VIOLATED,
              "detail": f"{len(out_of_order)} pairs of audit entries carry observation "
                        "sequences that do not increase in chain order"}
    else:
        i4 = {"status": HOLDS,
              "detail": "observation sequences increase strictly in audit chain order, "
                        "which is consistent with every observation being taken before "
                        "the enforcement that cites it"}
    i4["ordered_pairs"] = max(len(seqs) - 1, 0)

    # --- I6: the two logs are identity-bound to each other ---
    mismatched = [
        (entry, rec) for entry, rec in observed
        if entry.get("bound_principal") != rec.principal_id
    ]
    if not observed:
        i6 = {"status": i1["status"] if i1["status"] != PARTIAL else VIOLATED,
              "detail": "no observed enforcement to compare"}
    elif mismatched:
        i6 = {"status": VIOLATED,
              "detail": f"{len(mismatched)} audit entries name a different principal "
                        "than the observation they cite"}
    else:
        i6 = {"status": HOLDS,
              "detail": f"all {len(observed)} observed enforcements name the same "
                        "principal in both logs"}
    i6["compared"] = len(observed)

    return {
        "I1": i1,
        "I4": i4,
        "I6": i6,
        "holds": all(r["status"] == HOLDS for r in (i1, i4, i6)),
    }
