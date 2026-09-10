"""Fail-closed: no way out of the mediator is an exception.

The bug: _finish only caught AuditError. Audit is an injected dependency --
Mediator accepts any object at all with .append() -- so a backend that
raises OSError made it all the way out of evaluate(). Even _gated's own
fallback goes through _finish, so there was no second net.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from _setup import build, request  # noqa: E402

from axiomgate_kernel import ActionType, RiskLevel, Verdict  # noqa: E402


class ExplodingAudit:
    """Duck-typed audit backend that fails with something other than AuditError."""

    def append(self, record):
        raise OSError("disk full")

    def entries(self):
        return []


@pytest.mark.parametrize("action,risk", [
    (ActionType.EXECUTE.value, RiskLevel.LOW.value),    # would have become PERMIT
    (ActionType.COMMIT.value, RiskLevel.LOW.value),     # owner-mandatory
    (ActionType.EXECUTE.value, RiskLevel.HIGH.value),   # over the risk ceiling
])
def test_non_audit_backend_failure_is_still_a_verdict(action, risk):
    """An OSError from the audit backend should become a verdict, not an exception."""
    mediator, agent_key, _owner, _audit, _tmp = build()
    mediator._audit = ExplodingAudit()

    decision = mediator.evaluate(request(
        agent_key, action_type=action, domain="code",
        risk_level=risk, payload={"file": "a.py"},
    ))

    assert decision.verdict in (Verdict.DENY, Verdict.ESCALATE)
    assert decision.grant is None
    # Without this the test would be empty: it would pass even if the input
    # never reached the audit write and therefore never exercised the net.
    assert "audit.write_failed" in decision.applied_rules
    assert "audit.write_failed" in decision.applied_rules


def test_would_be_permit_is_downgraded_to_deny():
    """What would have become PERMIT is downgraded -- an unwritten log is no
    permission."""
    mediator, agent_key, _owner, _audit, _tmp = build()
    mediator._audit = ExplodingAudit()
    decision = mediator.evaluate(request(
        agent_key, action_type=ActionType.EXECUTE.value, domain="code",
        risk_level=RiskLevel.LOW.value, payload={"file": "a.py"},
    ))
    assert decision.verdict is Verdict.DENY


def test_failure_never_yields_a_permission():
    """The stronger claim: no failure may yield PERMIT."""
    mediator, agent_key, _owner, _audit, _tmp = build()
    mediator._audit = ExplodingAudit()
    decision = mediator.evaluate(request(
        agent_key, action_type=ActionType.EXECUTE.value, domain="code",
        risk_level=RiskLevel.LOW.value, payload={"file": "a.py"},
    ))
    assert decision.verdict is not Verdict.PERMIT


class _OddPrincipal:
    """Duck-typed principal lacking .principal_id."""


class BrokenAuthenticator:
    """Injected authenticator that returns a principal object the kernel does
    not understand.

    Authenticator is, just like audit, an injected dependency: the
    constructor accepts any object at all with .authenticate(). What comes
    back therefore does not have to be a Principal.
    """

    def __init__(self, inner):
        self._inner = inner

    def authenticate(self, canon):
        result = self._inner.authenticate(canon)
        if not result.ok:
            return result
        return type(result)(ok=True, reason=result.reason, rule=result.rule,
                            principal=_OddPrincipal())


class UnhashablePayload:
    """Canon whose payload hash fails -- same class of error, different line."""

    def __init__(self, inner):
        self._inner = inner

    def get(self, key, default=None):
        return self._inner.get(key, default)

    def full_payload_hash(self):
        raise RuntimeError("hash backend unavailable")

    def __getattr__(self, name):
        return getattr(self._inner, name)


def test_unusable_principal_is_a_verdict_not_an_exception():
    """The bug: _finish built the audit entry BEFORE its try -- the exception
    escaped.

    _finish is the last net: both _gated's fallback and every normal exit
    go through it. If it read `principal.principal_id` on an object without
    that attribute, AttributeError came out of evaluate() instead of a
    verdict.
    """
    mediator, agent_key, _owner, _audit, _tmp = build()
    mediator._authn = BrokenAuthenticator(mediator._authn)

    decision = mediator.evaluate(request(
        agent_key, action_type=ActionType.EXECUTE.value,
        domain="code", risk_level=RiskLevel.LOW.value))

    # Which branch catches it does not matter -- the requirement is that
    # evaluate() returns a verdict and no authorization. Here the error is
    # already caught in _gated's fallback, and _finish then manages to
    # describe it as None.
    assert decision.verdict is Verdict.DENY
    assert decision.grant is None
    assert decision.bound_principal is None


def test_payload_hash_failure_is_a_verdict_not_an_exception():
    """Same net, different line in the same dict: full_payload_hash() raises."""
    mediator, agent_key, _owner, _audit, _tmp = build()

    import axiomgate_kernel.mediator as mediator_module
    real_snapshot = mediator_module.snapshot_request
    mediator_module.snapshot_request = lambda req: UnhashablePayload(real_snapshot(req))
    try:
        decision = mediator.evaluate(request(
            agent_key, action_type=ActionType.EXECUTE.value,
            domain="code", risk_level=RiskLevel.LOW.value))
    finally:
        mediator_module.snapshot_request = real_snapshot

    assert decision.verdict is Verdict.DENY
    assert decision.grant is None
    assert "record.build_failed" in decision.applied_rules


@pytest.mark.parametrize("method", [
    "evaluate", "reenter", "decide_escalation", "create_evidence",
    "verify_evidence", "authorize_evidence", "update_policy",
])
def test_every_entry_point_returns_a_verdict(method):
    """Audit finding 2026-09-10: only evaluate() was covered.

    All seven entry points go through _gated and _finish, but that was a
    claim about the code -- not something that would fail if it stopped
    being true. With an audit backend that raises, each of them should
    return a verdict, never an exception.
    """
    mediator, agent_key, _owner, _audit, _tmp = build()
    mediator._audit = ExplodingAudit()

    decision = getattr(mediator, method)(request(
        agent_key, action_type=ActionType.EXECUTE.value,
        domain="code", risk_level=RiskLevel.LOW.value))

    assert decision.verdict in (Verdict.DENY, Verdict.ESCALATE)
    assert decision.grant is None
    # Without this the test would be empty: it would pass even if the input
    # never reached the audit write and therefore never exercised the net.
    assert "audit.write_failed" in decision.applied_rules
