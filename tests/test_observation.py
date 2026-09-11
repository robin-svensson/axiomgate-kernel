"""I1, I4 and I6 are MODEL-ONLY because the kernel keeps no observation log.

`docs/TRACEABILITY.md` marks three invariants MODEL-ONLY for one shared reason,
not three separate ones: they are all statements relating `obsLog` to
`enforceLog`, and the implementation has only the second. Every decision is
written to the audit chain. Nothing is written when the kernel *observes* a
request -- authenticates it and binds it to an identity -- so there is no
earlier record for an audit entry to be checked against.

The kernel almost certainly does the right thing: `Mediator._gated`
authenticates before it dispatches, so an identity-bound observation does
precede every enforcement that follows one. The problem is that this is a
property of the source code, provable only by reading it, and it disappears the
moment anyone rearranges that method. It is not checkable at runtime, not
checkable from a log, and not checkable by a customer who was not given the
source.

That is what these tests describe. They are about making three invariants
*answerable*, and about answering them honestly where the answer is bad: not
every audit entry has an observation, because the kernel denies some requests
before authentication can happen at all. A report that hid those would be worse
than no report.

Every test here fails against a kernel where observation.py does not exist.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from _setup import build, request  # noqa: E402

from axiomgate_kernel import (  # noqa: E402
    ActionType,
    Mediator,
    RiskLevel,
    Verdict,
    generate_key,
)
from axiomgate_kernel.observation import (  # noqa: E402
    ObservationError,
    ObservationLog,
    check_invariants,
)


def observed():
    """The example build, plus an observation log wired into the mediator.

    Built by hand rather than by mutating what build() returns: the log has to
    be present when the Mediator is constructed, and a test that reaches in
    afterwards would not prove that the constructor accepts it.
    """
    mediator, agent_key, owner_key, audit, tmp = build()
    obs = ObservationLog()
    watched = Mediator(
        authenticator=mediator._authn,
        registry=mediator._registry,
        audit=audit,
        provenance=mediator._provenance,
        policy=mediator._policy,
        observations=obs,
    )
    return watched, obs, audit, agent_key, owner_key


def act(mediator, key, risk=RiskLevel.LOW.value, principal="agent-a"):
    return mediator.evaluate(request(
        key, principal=principal, action_type=ActionType.EXECUTE.value,
        domain="code", risk_level=risk, payload={"file": "a.py"},
    ))


# --- the question has to be answerable at all -------------------------------

def test_a_kernel_with_no_observation_log_cannot_answer_the_question():
    """Fail-closed applies to the report itself. A kernel built without an
    observation log has no evidence either way, and the honest answer is
    "unobservable" -- never "holds". Unconfirmed is not true."""
    mediator, agent_key, _o, audit, _t = build()
    act(mediator, agent_key)

    report = check_invariants(None, audit.entries())
    for invariant in ("I1", "I4", "I6"):
        assert report[invariant]["status"] == "UNOBSERVABLE"
    assert report["holds"] is False


def test_an_observation_log_that_saw_nothing_is_not_a_pass():
    """An empty observation log against a non-empty audit chain means every
    enforcement is unexplained. Vacuous truth is the failure mode a check like
    this dies of -- the same one an empty pytest parametrisation had."""
    mediator, agent_key, _o, audit, _t = build()
    act(mediator, agent_key)

    report = check_invariants(ObservationLog(), audit.entries())
    assert report["I1"]["status"] == "VIOLATED"


# --- I1: every enforcement has an identity-bound observation ----------------

def test_every_authenticated_decision_leaves_an_observation():
    """I1. The observation is what binds a decision to an identity *before*
    the decision exists. Without a record of it, 'the kernel authenticated
    first' is a claim about source code, not about this run."""
    mediator, obs, audit, agent_key, _o = observed()
    decision = act(mediator, agent_key)
    assert decision.verdict is Verdict.PERMIT

    records = obs.entries()
    assert len(records) == 1
    assert records[0].principal_id == "agent-a"

    report = check_invariants(obs, audit.entries())
    assert report["I1"]["status"] == "HOLDS"


# --- I4: observation precedes enforcement -----------------------------------

def test_the_observation_precedes_the_enforcement_it_belongs_to():
    """I4. Ordering is the invariant, so the check needs an ordering it can
    read -- a sequence number written into both records, not two wall-clock
    timestamps that can tie or run backwards under a clock adjustment."""
    mediator, obs, audit, agent_key, _o = observed()
    act(mediator, agent_key)
    act(mediator, agent_key)

    entries = audit.entries()
    assert [e["observation_seq"] for e in entries] == [1, 2]
    assert [r.seq for r in obs.entries()] == [1, 2]

    report = check_invariants(obs, audit.entries())
    assert report["I4"]["status"] == "HOLDS"


# --- I6: the two logs are identity-bound ------------------------------------

def test_the_observation_and_the_enforcement_name_the_same_principal():
    """I6. Two logs that each look correct can still disagree with each other.
    Consistency is a claim about the pair, and only a check over both can make
    it."""
    mediator, obs, audit, agent_key, _o = observed()
    act(mediator, agent_key)

    entry = audit.entries()[0]
    record = obs.entries()[0]
    assert entry["bound_principal"] == record.principal_id

    report = check_invariants(obs, audit.entries())
    assert report["I6"]["status"] == "HOLDS"


def test_a_disagreeing_pair_is_caught():
    """If the check cannot fail it is not a check. A tampered audit entry
    naming a different principal than the observation must be reported."""
    mediator, obs, audit, agent_key, _o = observed()
    act(mediator, agent_key)

    entries = audit.entries()
    entries[0]["bound_principal"] = "someone-else"

    report = check_invariants(obs, entries)
    assert report["I6"]["status"] == "VIOLATED"
    assert report["holds"] is False


# --- the honest gap ---------------------------------------------------------

def test_a_denial_reached_before_authentication_has_no_observation():
    """The kernel denies an unavailable mediator, an uncanonicalizable request
    and a failed authentication *before* any identity exists. Those enforcement
    records genuinely have no observation, and I1 as the model states it does
    not hold over them. The report names them rather than quietly excluding
    them -- an excluded case is how a check becomes decoration."""
    mediator, obs, audit, agent_key, _o = observed()
    act(mediator, agent_key)
    mediator.set_available(False)
    denied = act(mediator, agent_key)
    assert denied.verdict is Verdict.DENY

    report = check_invariants(obs, audit.entries())
    assert report["I1"]["status"] == "PARTIAL"
    assert report["I1"]["unobserved_enforcements"] == 1
    # Naming the reason is the difference between a report and a number.
    assert "mediator.unavailable" in report["I1"]["unobserved_rules"]


def test_an_unauthenticated_request_is_the_same_case():
    """A signature the kernel rejects never produces an identity, so it never
    produces an observation. Same shape as the unavailable case, different
    door, and both have to land in the same bucket or the bucket is arbitrary.

    The successful call alongside it is not decoration: with only the rejected
    one, nothing at all is observed and the status is VIOLATED rather than
    PARTIAL. PARTIAL means "some", and "some" needs at least one of each."""
    mediator, obs, audit, agent_key, _o = observed()
    act(mediator, agent_key)
    act(mediator, generate_key())  # a key the store has never seen

    report = check_invariants(obs, audit.entries())
    assert report["I1"]["status"] == "PARTIAL"
    assert report["I1"]["unobserved_enforcements"] == 1


# --- the log itself ---------------------------------------------------------

def test_the_observation_log_is_append_only():
    """An observation log that can be rewritten proves nothing about ordering,
    because the ordering could have been written afterwards."""
    obs = ObservationLog()
    obs.record("agent-a", "req-1", "hash-1")
    with pytest.raises(ObservationError):
        obs.entries()[0].seq = 99


def test_the_returned_entries_are_a_copy():
    """entries() handing out the live list would let a caller append to the
    log through the reader, which is the same hole by a slower route."""
    obs = ObservationLog()
    obs.record("agent-a", "req-1", "hash-1")
    obs.entries().clear()
    assert len(obs.entries()) == 1
