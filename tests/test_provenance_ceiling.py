"""R1: provenance bounds authority, not just the capability.

Until 2026-09-10, principal_context.py was doctrine without effect. The
module defined mandates, ceilings per mandate, and monotonic propagation to
subagents -- and no verdict read it. An agent with a capability up to MEDIUM
was allowed to do MEDIUM even when the mandate it was operating under only
reached LOW.

The requirement from docs/ROADMAP.md R1: effective ceiling =
min(capability.risk_ceiling, the mandate's ceiling), the context read from a
bound PrincipalContext, and a MISSING context fails closed -- never a
fallback to the most permissive option.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from _setup import build, request  # noqa: E402

from axiomgate_kernel import ActionType, RiskLevel, Verdict  # noqa: E402
from axiomgate_kernel.principal_context import (  # noqa: E402
    PrincipalContext,
    principal_context_scope,
    set_principal_context,
)


def strict():
    """A mediator that requires a bound context. Same build otherwise."""
    mediator, agent_key, owner_key, audit, tmp = build()
    mediator.require_principal_context = True
    return mediator, agent_key, owner_key, audit, tmp


def ctx(mandate, provenance="direct"):
    return PrincipalContext(
        principal_id="agent-a",
        parent_principal_id="owner",
        session_id="s1",
        mandate=mandate,
        provenance=provenance,
    )


def execute(mediator, key, risk, action=ActionType.EXECUTE.value):
    return mediator.evaluate(request(
        key, action_type=action, domain="code",
        risk_level=risk, payload={"file": "a.py"},
    ))


# --- Det saknade contextet -------------------------------------------------

def test_missing_context_is_denied_not_defaulted():
    """No bound context must never mean 'no ceiling'.

    That is the entire difference between fail-closed and fail-open: an
    integrator who forgets to set the context should be stopped, not
    silently given the widest frame.
    """
    mediator, agent_key, _o, _a, _t = strict()
    decision = execute(mediator, agent_key, RiskLevel.LOW.value)
    assert decision.verdict is Verdict.DENY
    assert "authz.no_principal_context" in decision.applied_rules
    assert decision.grant is None


def test_context_without_mandate_is_denied():
    """A context without a mandate carries no frame. The module itself says:
    must escalate."""
    mediator, agent_key, _o, _a, _t = strict()
    with principal_context_scope(ctx(None)):
        decision = execute(mediator, agent_key, RiskLevel.LOW.value)
    assert decision.verdict is Verdict.DENY
    assert "authz.no_mandate" in decision.applied_rules


def test_unparseable_mandate_is_denied():
    """A mandate string that cannot be parsed is not an empty mandate."""
    mediator, agent_key, _o, _a, _t = strict()
    with principal_context_scope(ctx("execute:expires:not-a-date")):
        decision = execute(mediator, agent_key, RiskLevel.LOW.value)
    assert decision.verdict is Verdict.DENY
    assert "authz.mandate_unparseable" in decision.applied_rules


def test_expired_mandate_is_denied():
    mediator, agent_key, _o, _a, _t = strict()
    with principal_context_scope(ctx("execute:expires:2020-01-01T00:00:00Z")):
        decision = execute(mediator, agent_key, RiskLevel.LOW.value)
    assert decision.verdict is Verdict.DENY
    assert "authz.mandate_invalid" in decision.applied_rules


# --- Taket ----------------------------------------------------------------

def test_mandate_ceiling_binds_below_the_capability():
    """The capability reaches MEDIUM, the mandate 'propose' only reaches LOW.

    PROPOSE lies within both scopes -- so it is exclusively the RISK CEILING
    that separates them, which is what this test is meant to prove. Without
    R1 this gave PERMIT: the capability was the only thing that counted.
    """
    mediator, agent_key, _o, _a, _t = strict()
    with principal_context_scope(ctx("propose")):
        decision = execute(mediator, agent_key, RiskLevel.MEDIUM.value,
                           action=ActionType.PROPOSE.value)
    assert decision.verdict is Verdict.DENY
    assert "authz.provenance_risk_ceiling" in decision.applied_rules
    # Not the capability's own ceiling -- that one handled MEDIUM.
    assert "authz.risk_ceiling" not in decision.applied_rules


def test_capability_still_binds_below_the_mandate():
    """The ceiling is a minimum of two, not a replacement of one by the other.

    The mandate 'full' reaches HIGH, the capability only MEDIUM. HIGH is
    also owner-mandatory, so the outcome is an escalation -- not a
    permission.
    """
    mediator, agent_key, _o, _a, _t = strict()
    with principal_context_scope(ctx("full")):
        decision = execute(mediator, agent_key, RiskLevel.HIGH.value)
    assert decision.verdict is not Verdict.PERMIT
    assert decision.grant is None


def test_action_outside_the_mandate_is_denied():
    """The mandate 'read-only' does not reach EXECUTE, no matter the capability."""
    mediator, agent_key, _o, _a, _t = strict()
    with principal_context_scope(ctx("read-only")):
        decision = execute(mediator, agent_key, RiskLevel.LOW.value)
    assert decision.verdict is Verdict.DENY
    assert "authz.mandate_action_out_of_scope" in decision.applied_rules


def test_within_both_ceilings_still_permits():
    """The check must not be a blanket no. 'execute' + LOW goes through."""
    mediator, agent_key, _o, _a, _t = strict()
    with principal_context_scope(ctx("execute")):
        decision = execute(mediator, agent_key, RiskLevel.LOW.value)
    assert decision.verdict is Verdict.PERMIT
    assert decision.grant is not None


# --- Auditen --------------------------------------------------------------

def test_the_audit_record_says_which_bound_applied():
    """A reader should be able to see which ceiling applied, not just the
    outcome.

    ROADMAP R1 condition 2: the provenance and the effective ceiling are
    recorded.
    """
    mediator, agent_key, _o, audit, _t = strict()
    with principal_context_scope(ctx("propose", provenance="delegated")):
        execute(mediator, agent_key, RiskLevel.MEDIUM.value,
                action=ActionType.PROPOSE.value)
    entry = audit.entries()[-1]
    assert entry["provenance"] == "delegated"
    assert entry["effective_risk_ceiling"] == "LOW"
    assert entry["mandate_id"].startswith("mandate-propose-")


def test_a_missing_context_is_visible_in_the_audit_too():
    """What was denied because the context was missing should show in the log."""
    mediator, agent_key, _o, audit, _t = strict()
    execute(mediator, agent_key, RiskLevel.LOW.value)
    entry = audit.entries()[-1]
    assert entry["provenance"] is None
    assert entry["mandate_id"] is None


# --- Backward compatibility -------------------------------------------------

def test_the_default_mediator_is_unchanged():
    """The flag is off by default: existing integrators see no difference.

    This is a deliberate deviation and it is written out in ROADMAP R1 --
    without the flag there is no provenance ceiling at all, and that is a
    known gap, not a sneaked-in hole.
    """
    mediator, agent_key, _o, _a, _t = build()
    assert mediator.require_principal_context is False
    decision = execute(mediator, agent_key, RiskLevel.MEDIUM.value)
    assert decision.verdict is Verdict.PERMIT


def test_the_flag_can_be_set_at_construction():
    """It must be settable where the mediator is built, not only afterward."""
    from axiomgate_kernel import Mediator
    import inspect
    sig = inspect.signature(Mediator.__init__)
    assert "require_principal_context" in sig.parameters
    assert sig.parameters["require_principal_context"].default is False


# --- The audit record describes the frame that actually applied ------------

def test_a_swapped_context_cannot_rewrite_the_audit_record():
    """The log claimed the wrong mandate if the provenance backend swapped
    the context in the meantime.

    Until 2026-09-10, _audit_record re-read the bound context instead of
    just carrying the CapabilityCheck that had already decided. Between
    those two lines, self._provenance.check() runs -- an INJECTED
    dependency, the same trust level as audit and authenticator. A backend
    that swapped out the context there got the decision computed on one
    mandate and logged on another, and a reviewer could not see which frame
    granted the permission.
    """
    from axiomgate_kernel.provenance import ProvenanceKind, ProvenanceResult

    mediator, agent_key, _o, audit, _t = strict()

    class SwapsTheContext:
        """A provenance backend that swaps the mandate mid-decision."""

        def check(self):
            set_principal_context(ctx("read-only", provenance="delegated"))
            return ProvenanceResult(ProvenanceKind.MATCH, "ok")

    mediator._provenance = SwapsTheContext()

    with principal_context_scope(ctx("full", provenance="direct")):
        decision = execute(mediator, agent_key, RiskLevel.MEDIUM.value,
                           action=ActionType.PROPOSE.value)

    assert decision.verdict is Verdict.PERMIT
    entry = audit.entries()[-1]
    # The decision was computed under "full"/direct. The log should say the same.
    assert entry["provenance"] == "direct"
    assert entry["mandate_id"].startswith("mandate-full-")
    assert entry["effective_risk_ceiling"] == "MEDIUM"


# --- The same requirement on the reentry path -------------------------------

def strict_high():
    """Like strict(), but the agent's capability reaches HIGH.

    HIGH is owner-mandatory: evaluate gives ESCALATE, the owner reserves,
    and reenter is then the only path to PERMIT. With the MEDIUM ceiling
    from build(), the reentry dies on authz.risk_ceiling and the PERMIT
    path is never exercised.
    """
    from datetime import datetime, timedelta, timezone

    from axiomgate_kernel import (
        ActionType, CapabilityRegistry, ProvisioningToken, Role,
        make_capability,
    )

    mediator, agent_key, owner_key, audit, tmp = strict()
    token = ProvisioningToken()
    registry = CapabilityRegistry()
    now = datetime.now(timezone.utc)
    for cap_id, pid, role in (
        ("cap-a", "agent-a", Role.R_ENG), ("cap-owner", "owner", Role.R_DEC),
    ):
        registry.register(make_capability(
            capability_id=cap_id, principal_id=pid, role=role, domains=["code"],
            action_types=list(ActionType) if role is Role.R_DEC else [
                ActionType.INSPECT, ActionType.PROPOSE, ActionType.EXECUTE],
            risk_ceiling=RiskLevel.HIGH, issued_by="Owner",
            issued_at=now, expires_at=now + timedelta(hours=1),
        ), token)
    registry.seal(token)
    mediator._registry = registry
    return mediator, agent_key, owner_key, audit, tmp


def reserve_then_reenter(mediator, agent_key, owner_key, *, before_reenter=None):
    """Runs the full cycle evaluate -> decide_escalation -> reenter under the
    mandate "full".

    The same request_id and payload in both steps: the reserved grant binds
    both, so a new request_id would be rejected by consume_if_valid.
    """
    from uuid import uuid4

    req_id = f"req-{uuid4().hex[:8]}"
    payload = {"file": "a.py"}
    fields = dict(
        action_type=ActionType.EXECUTE.value, domain="code",
        risk_level=RiskLevel.HIGH.value, payload=payload, request_id=req_id,
    )

    with principal_context_scope(ctx("full", provenance="direct")):
        first = mediator.evaluate(request(agent_key, **fields))
    assert first.verdict is Verdict.ESCALATE, first.applied_rules

    mediator.decide_escalation(request(
        owner_key, principal="owner",
        escalation_id=first.escalation_id, owner_decision="permit",
    ))

    if before_reenter is not None:
        before_reenter(mediator)

    with principal_context_scope(ctx("full", provenance="direct")):
        return mediator.reenter(request(
            agent_key, escalation_id=first.escalation_id, **fields))


def test_reentry_permit_records_the_frame_it_was_granted_under():
    """Reentry PERMIT logged None on all three frame fields -- with no
    attack involved.

    frame was only threaded through _evaluate_authenticated. In
    _reenter_authenticated, frame=check was set only on the DENY branch
    right after check_capability; the PERMIT path further down called
    _permit without frame. The check DID RUN and did set the frame -- the
    record just dropped it, so a reviewer of a reentry decision could not
    see which mandate applied.
    """
    mediator, agent_key, owner_key, audit, _t = strict_high()

    decision = reserve_then_reenter(mediator, agent_key, owner_key)

    assert decision.verdict is Verdict.PERMIT, decision.applied_rules
    entry = audit.entries()[-1]
    assert entry["provenance"] == "direct"
    assert entry["mandate_id"].startswith("mandate-full-")
    assert entry["effective_risk_ceiling"] == "HIGH"


def test_a_swapped_context_cannot_rewrite_the_reentry_audit_record():
    """The same attack as on the evaluate path, but against the reentry.

    check_capability runs before self._provenance.check() here too, so a
    backend that swaps the context in between must not move the frame in
    the log.
    """
    from axiomgate_kernel.provenance import ProvenanceKind, ProvenanceResult

    mediator, agent_key, owner_key, audit, _t = strict_high()

    class SwapsTheContext:
        def check(self):
            set_principal_context(ctx("read-only", provenance="delegated"))
            return ProvenanceResult(ProvenanceKind.MATCH, "ok")

    decision = reserve_then_reenter(
        mediator, agent_key, owner_key,
        before_reenter=lambda m: setattr(m, "_provenance", SwapsTheContext()),
    )

    assert decision.verdict is Verdict.PERMIT, decision.applied_rules
    entry = audit.entries()[-1]
    assert entry["provenance"] == "direct"
    assert entry["mandate_id"].startswith("mandate-full-")
    assert entry["effective_risk_ceiling"] == "HIGH"


def test_a_reentry_denied_after_the_check_still_records_the_frame():
    """Even a DENY downstream of the check should describe the frame it was
    judged under.

    provenance.mismatch sits after check_capability: the frame has been
    computed, it is the provenance that fails to hold. The record said
    None on all three frame fields there too. (A DENY UPSTREAM of the
    check -- e.g. reentry.already_resolved -- should instead keep saying
    None: no frame was computed.)
    """
    from axiomgate_kernel.provenance import ProvenanceKind, ProvenanceResult

    mediator, agent_key, owner_key, audit, _t = strict_high()

    class Mismatch:
        def check(self):
            return ProvenanceResult(ProvenanceKind.MISMATCH, "head moved")

    decision = reserve_then_reenter(
        mediator, agent_key, owner_key,
        before_reenter=lambda m: setattr(m, "_provenance", Mismatch()),
    )

    assert decision.verdict is Verdict.DENY
    assert "provenance.mismatch" in decision.applied_rules
    entry = audit.entries()[-1]
    assert entry["provenance"] == "direct"
    assert entry["mandate_id"].startswith("mandate-full-")
    assert entry["effective_risk_ceiling"] == "HIGH"


def test_a_reentry_denied_before_the_check_records_no_frame():
    """The counter-proof: upstream of the check there is no frame, and then
    it should be None.

    Covering a gap with "write something" is the same mistake as writing 0
    for a missing value. reentry.already_resolved decides before
    check_capability runs.
    """
    mediator, agent_key, owner_key, audit, _t = strict_high()

    granted = reserve_then_reenter(mediator, agent_key, owner_key)
    assert granted.verdict is Verdict.PERMIT

    with principal_context_scope(ctx("full", provenance="direct")):
        second = mediator.reenter(request(
            agent_key, action_type=ActionType.EXECUTE.value, domain="code",
            risk_level=RiskLevel.HIGH.value, payload={"file": "a.py"},
            escalation_id=granted.escalation_id,
        ))

    assert second.verdict is Verdict.DENY
    assert "reentry.already_resolved" in second.applied_rules
    entry = audit.entries()[-1]
    assert entry["provenance"] is None
    assert entry["mandate_id"] is None
    assert entry["effective_risk_ceiling"] is None


def test_an_out_of_scope_action_logs_no_effective_ceiling():
    """If the action is denied on scope, no ceiling was ever tested -- so
    nothing should stand there.

    Finding 2026-09-10, same family as the false traceability: when
    'authz.mandate_action_out_of_scope' fired, the log wrote the
    CAPABILITY'S own ceiling into effective_risk_ceiling ('MEDIUM'),
    because `ceiling` had not yet been recomputed via effective_ceiling().
    The record therefore claimed MEDIUM was the frame that applied. No
    frame applied: the decision was made before any ceiling comparison,
    and the mandate's own ceiling never entered the picture. A missing
    value is not a ceiling.
    """
    mediator, agent_key, _o, audit, _t = strict()
    with principal_context_scope(ctx("read-only")):
        decision = execute(mediator, agent_key, RiskLevel.LOW.value)
    assert decision.verdict is Verdict.DENY
    assert "authz.mandate_action_out_of_scope" in decision.applied_rules
    entry = audit.entries()[-1]
    assert entry["effective_risk_ceiling"] is None
    # The mandate, however, is known and should stay: a reader must be able
    # to see WHICH mandate fell short.
    assert entry["mandate_id"].startswith("mandate-read-only-")
    assert entry["provenance"] == "direct"


def test_an_expired_mandate_logs_no_effective_ceiling():
    """An invalid mandate bounds nothing -- not even to its own ceiling."""
    mediator, agent_key, _o, audit, _t = strict()
    with principal_context_scope(ctx("execute:expires:2020-01-01T00:00:00Z")):
        decision = execute(mediator, agent_key, RiskLevel.LOW.value)
    assert decision.verdict is Verdict.DENY
    assert "authz.mandate_invalid" in decision.applied_rules
    entry = audit.entries()[-1]
    assert entry["effective_risk_ceiling"] is None
    assert entry["mandate_id"].startswith("mandate-execute-")


def test_the_ceiling_that_did_apply_is_still_written():
    """Counter-proof: when the ceiling REALLY bound the decision, it must
    not become None.

    Without this, the fix above could be a blanket None and the tests
    would still pass.
    """
    mediator, agent_key, _o, audit, _t = strict()
    with principal_context_scope(ctx("propose")):
        decision = execute(mediator, agent_key, RiskLevel.MEDIUM.value,
                           action=ActionType.PROPOSE.value)
    assert "authz.provenance_risk_ceiling" in decision.applied_rules
    assert audit.entries()[-1]["effective_risk_ceiling"] == "LOW"


def test_without_the_flag_no_effective_ceiling_is_claimed():
    """When no context is required, there is no effective ceiling -- the
    docstring already said so.

    The CapabilityCheck docstring has all along claimed that
    `effective_risk_ceiling` is None when no context is required. The
    code nonetheless wrote in the capability's own ceiling ('MEDIUM'), in
    the very case where by definition there is no provenance frame to
    compute. The documentation was right and the code was wrong, not the
    other way around.
    """
    mediator, agent_key, _o, audit, _t = build()[:5]
    assert mediator.require_principal_context is False
    decision = execute(mediator, agent_key, RiskLevel.LOW.value)
    assert decision.verdict is Verdict.PERMIT
    entry = audit.entries()[-1]
    assert entry["effective_risk_ceiling"] is None
    assert entry["mandate_id"] is None
