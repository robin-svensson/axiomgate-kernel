"""I5 is MODEL-ONLY because nothing records that an execution happened.

`docs/TRACEABILITY.md` marks I5 `MODEL-ONLY` for the same single reason I1, I4
and I6 carried until the observation log was written: the invariant relates two
logs, and the kernel keeps only one of them. I5 says every execution has a
matching observation. Execution in this kernel is the redemption of a
`ReservedGrant` -- `ReservedGrantStore.consume_if_valid` is the only way to
redeem one -- and that redemption writes nothing anywhere.

The `consumed` flag on the grant is not a substitute, and the reason is
`unconsume`. A redemption is rolled back when downstream audit logging fails,
and the flag goes back to `False`. A log that appended on consume and stopped
there would carry an execution that never happened, and would keep carrying it
after the rollback. That is worse than no log: it reports an execution the
kernel deliberately undid.

So the record has to be able to say that something was taken back. These tests
describe an execution log that distinguishes three states -- executed, rolled
back, never happened -- and a check that will not call I5 satisfied from an
empty set.

Every test here fails against a kernel where ExecutionLog does not exist.
"""

import sys
from datetime import timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from axiomgate_kernel.execution import (  # noqa: E402
    ExecutionError,
    ExecutionLog,
    check_execution_invariant,
)
from axiomgate_kernel.grant import ReasonClass, ReservedGrantStore  # noqa: E402
from axiomgate_kernel.observation import (  # noqa: E402
    HOLDS,
    PARTIAL,
    UNOBSERVABLE,
    VIOLATED,
    ObservationLog,
)


def _store():
    return ReservedGrantStore(ttl=timedelta(hours=1))


def _reserve(store, executions=None, *, request_id="req-1", principal_id="p-1"):
    """Reserve one grant and hand back what consume_if_valid needs to match it."""
    store.create_pending_context(
        escalation_id="esc-1",
        principal_id=principal_id,
        agent_id="a-1",
        request_id=request_id,
        action="read",
        domain="d",
        risk_level="low",
        payload_hash="h",
        capability_id="c-1",
        capability_scope_hash="s",
        policy_version="1",
        policy_hash="ph",
        provenance_kind="k",
        provenance_identity="pi",
        reason_class=ReasonClass.OTHER,
    )
    return dict(
        escalation_id="esc-1",
        principal_id=principal_id,
        agent_id="a-1",
        request_id=request_id,
        action="read",
        domain="d",
        risk_level="low",
        payload_hash="h",
        capability_id="c-1",
        capability_scope_hash="s",
        policy_hash="ph",
        provenance_identity="pi",
    )


# --- the log itself ---------------------------------------------------------

def test_the_store_takes_the_log_as_a_constructor_argument():
    """Reaching into a private attribute is not wiring. The log has to be
    passed where a reader of the call site can see it, like observations= on
    Mediator, and it has to stay opt-in for the same reason."""
    log = ExecutionLog()
    store = ReservedGrantStore(ttl=timedelta(hours=1), executions=log)
    args = _reserve(store)
    store.attach_owner_decision("esc-1", "permit")
    store.consume_if_valid(**args)

    assert len(log.entries()) == 1


def test_a_rolled_back_redemption_is_marked_not_deleted():
    """unconsume exists: a redemption is undone when downstream audit logging
    fails. A log that only appends carries an execution that never happened.
    Deleting the record instead would lose that it was ever attempted, which is
    the thing an auditor most wants to see."""
    log = ExecutionLog()
    store = ReservedGrantStore(ttl=timedelta(hours=1), executions=log)
    args = _reserve(store)
    store.attach_owner_decision("esc-1", "permit")
    store.consume_if_valid(**args)
    store.unconsume("esc-1")

    entries = log.entries()
    assert len(entries) == 1
    assert entries[0].rolled_back is True


def test_a_failed_redemption_records_nothing():
    """A GrantError means no execution happened. Recording the attempt would
    make the log answer 'yes' to 'did this execute?' for every request that was
    correctly refused."""
    log = ExecutionLog()
    store = ReservedGrantStore(ttl=timedelta(hours=1), executions=log)
    args = _reserve(store)
    # No owner permit attached: consume_if_valid must refuse.
    with pytest.raises(Exception):
        store.consume_if_valid(**args)

    assert log.entries() == []


def test_the_execution_log_is_append_only():
    """Same reason as the observation log: evidence a caller can rewrite is
    not evidence. A frozen dataclass would not do -- FrozenInstanceError is an
    AttributeError, which surrounding code swallows out of habit."""
    log = ExecutionLog()
    rec = log.record(request_id="r", principal_id="p", escalation_id="e")
    with pytest.raises(ExecutionError):
        rec.request_id = "other"


def test_the_returned_entries_are_a_copy():
    """entries() handing back the live list lets a caller append to the record
    of what executed."""
    log = ExecutionLog()
    log.record(request_id="r", principal_id="p", escalation_id="e")
    log.entries().append("forged")
    assert len(log.entries()) == 1


def test_seq_starts_at_one():
    """`if seq:` on a legitimate zero reads as absence. Same decision as the
    observation log, for the same reason."""
    log = ExecutionLog()
    assert log.record(request_id="r", principal_id="p", escalation_id="e").seq == 1


# --- the invariant ----------------------------------------------------------

def test_no_execution_log_cannot_answer_the_question():
    """A kernel built without the log has no evidence either way. Answering
    HOLDS there is the vacuous-truth failure the four states exist to stop."""
    report = check_execution_invariant(None, ObservationLog())
    assert report["status"] == UNOBSERVABLE
    assert report["holds"] is False


def test_an_execution_without_a_matching_observation_is_violated():
    """This is I5 itself. An execution whose request_id appears in no
    observation means something ran that the kernel never saw arrive."""
    executions = ExecutionLog()
    executions.record(request_id="ghost", principal_id="p-1", escalation_id="e")

    report = check_execution_invariant(executions, ObservationLog())
    assert report["status"] == VIOLATED


def test_an_execution_matched_by_an_observation_holds():
    """The honest case has to pass, or the check is a warning banner."""
    obs = ObservationLog()
    obs.record("p-1", "req-1", "hash")
    executions = ExecutionLog()
    executions.record(request_id="req-1", principal_id="p-1", escalation_id="e")

    report = check_execution_invariant(executions, obs)
    assert report["status"] == HOLDS
    assert report["holds"] is True


def test_a_rolled_back_execution_needs_no_observation():
    """It did not execute. Demanding an observation for it would report VIOLATED
    on a kernel that behaved correctly, and a check that cries wolf on correct
    behaviour gets turned off.

    Not VIOLATED, and not HOLDS either: an undone execution confirms nothing, so
    the answer is the same PARTIAL an empty log gets. This asserted HOLDS in its
    first version, which let one rollback stand in for a checked invariant."""
    executions = ExecutionLog()
    rec = executions.record(request_id="ghost", principal_id="p-1", escalation_id="e")
    executions.mark_rolled_back(rec.seq)

    report = check_execution_invariant(executions, ObservationLog())
    assert report["status"] == PARTIAL
    assert report["unmatched"] == []
    assert report["rolled_back"] == [rec.seq]


def test_an_execution_naming_a_different_principal_is_violated():
    """The observation exists for that request, but bound to someone else.
    Matching on request_id alone would call that a pass -- which is exactly the
    I6 failure, one log further along."""
    obs = ObservationLog()
    obs.record("p-1", "req-1", "hash")
    executions = ExecutionLog()
    executions.record(request_id="req-1", principal_id="p-2", escalation_id="e")

    report = check_execution_invariant(executions, obs)
    assert report["status"] == VIOLATED


def test_an_empty_execution_log_beside_observations_is_partial_not_holds():
    """Nothing executed. That is not evidence that execution is observed --
    it is evidence of nothing, and the difference is the whole point of having
    four states instead of a boolean."""
    obs = ObservationLog()
    obs.record("p-1", "req-1", "hash")

    report = check_execution_invariant(ExecutionLog(), obs)
    assert report["status"] == PARTIAL
    assert report["holds"] is False


# --- the whole chain through a real kernel -----------------------------------

def test_a_log_of_nothing_but_rollbacks_is_not_a_pass():
    """An empty execution log reports PARTIAL because nothing was checked. A log
    holding two entries that were both rolled back is the same fact in a
    different shape -- zero confirmed executions -- and it reported HOLDS.

    An operator reading HOLDS has been told the invariant was checked against
    something. It was checked against nothing, and the log looking busy is what
    makes this worse than the empty case rather than better."""
    execs, obs = ExecutionLog(), ObservationLog()
    for i in range(2):
        rec = execs.record(request_id=f"r{i}", principal_id="agent-a", escalation_id=None)
        execs.mark_rolled_back(rec.seq)

    report = check_execution_invariant(execs, obs)
    assert report["status"] == PARTIAL, report["detail"]
    assert report["holds"] is False
    assert report["matched"] == []
    assert len(report["rolled_back"]) == 2


def test_one_real_execution_still_holds_alongside_rollbacks():
    """The fix above must not turn rollbacks into contamination. A run that
    executed once and took another one back has confirmed the invariant on the
    one that counted, and reporting PARTIAL there would make the check useless
    for any kernel that ever rolls anything back."""
    execs, obs = ExecutionLog(), ObservationLog()
    obs.record("agent-a", "r-live", b"hash")
    execs.record(request_id="r-live", principal_id="agent-a", escalation_id=None)
    undone = execs.record(request_id="r-undone", principal_id="agent-a", escalation_id=None)
    execs.mark_rolled_back(undone.seq)

    report = check_execution_invariant(execs, obs)
    assert report["status"] == HOLDS, report["detail"]
    assert report["matched"] == [1]
    assert report["rolled_back"] == [2]


def test_two_observations_sharing_a_request_id_report_the_later_one():
    """Characterisation, not regression: the lookup is keyed on request_id, so
    a second observation with the same one replaces the first. An execution
    matching only the replaced observation is reported VIOLATED even though a
    matching observation exists in the log.

    That direction is the safe one -- a false alarm, never a silent pass -- and
    nothing upstream enforces request_id uniqueness, so it is written down here
    rather than left for somebody to rediscover as a bug."""
    execs, obs = ExecutionLog(), ObservationLog()
    obs.record("agent-a", "shared", b"hash")
    obs.record("agent-b", "shared", b"hash")
    execs.record(request_id="shared", principal_id="agent-a", escalation_id=None)

    report = check_execution_invariant(execs, obs)
    assert report["status"] == VIOLATED
    assert "agent-b" in report["unmatched"][0]["why"]


def test_a_real_escalation_cycle_produces_a_matched_execution():
    """The unit tests above build the two logs by hand, which proves the check
    and not the wiring. This runs the only path that reaches an execution --
    evaluate -> decide_escalation -> reenter -> consume_if_valid -- through a
    real Mediator with both logs attached, and asks I5 afterwards.

    Without it, the kernel could pass every test above and still never call
    ExecutionLog.record, because nothing else exercises that call site."""
    from datetime import datetime, timezone
    from uuid import uuid4

    from axiomgate_kernel import (
        ActionType,
        CapabilityRegistry,
        Mediator,
        ProvisioningToken,
        RiskLevel,
        Role,
        Verdict,
        make_capability,
    )
    from axiomgate_kernel.observation import ObservationLog
    from _setup import build, request

    base, agent_key, owner_key, audit, tmp = build()
    obs, execs = ObservationLog(), ExecutionLog()

    # build() caps the agent at MEDIUM, and HIGH is what makes the action
    # owner-mandatory. With the MEDIUM ceiling the reentry dies on
    # authz.risk_ceiling and the redemption -- the only thing that writes to the
    # execution log -- is never reached.
    registry, token = CapabilityRegistry(), ProvisioningToken()
    now = datetime.now(timezone.utc)
    for cap_id, pid, role in (("cap-a", "agent-a", Role.R_ENG),
                              ("cap-owner", "owner", Role.R_DEC)):
        registry.register(make_capability(
            capability_id=cap_id, principal_id=pid, role=role, domains=["code"],
            action_types=list(ActionType) if role is Role.R_DEC else [
                ActionType.INSPECT, ActionType.PROPOSE, ActionType.EXECUTE],
            risk_ceiling=RiskLevel.HIGH, issued_by="Owner",
            issued_at=now, expires_at=now + timedelta(hours=1),
        ), token)
    registry.seal(token)

    mediator = Mediator(
        authenticator=base._authn, registry=registry, audit=audit,
        provenance=base._provenance, policy=base._policy,
        observations=obs, executions=execs,
    )

    req_id = f"req-{uuid4().hex[:8]}"
    fields = dict(action_type=ActionType.EXECUTE.value, domain="code",
                  risk_level=RiskLevel.HIGH.value, payload={"file": "a.py"},
                  request_id=req_id)

    first = mediator.evaluate(request(agent_key, **fields))
    assert first.verdict is Verdict.ESCALATE, first.applied_rules
    mediator.decide_escalation(request(
        owner_key, principal="owner",
        escalation_id=first.escalation_id, owner_decision="permit"))
    final = mediator.reenter(request(agent_key, escalation_id=first.escalation_id, **fields))
    assert final.verdict is Verdict.PERMIT, final.applied_rules

    assert len(execs.entries()) == 1
    report = check_execution_invariant(execs, obs)
    assert report["status"] == HOLDS, report["detail"]
    assert report["holds"] is True
