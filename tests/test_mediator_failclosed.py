"""Fail-closed: ingen vag ut ur mediatorn ar ett undantag.

Buggen: _finish fangade bara AuditError. Audit ar ett injicerat beroende --
Mediator tar emot vilket objekt som helst med .append() -- sa en backend som
kastar OSError tog sig hela vagen ut ur evaluate(). Aven _gated:s egen
fallback gar via _finish, sa det fanns inget andra natet.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from _setup import build, request  # noqa: E402

from axiomgate_kernel import ActionType, RiskLevel, Verdict  # noqa: E402


class ExplodingAudit:
    """Duck-typad auditbackend som misslyckas med nagot annat an AuditError."""

    def append(self, record):
        raise OSError("disk full")

    def entries(self):
        return []


@pytest.mark.parametrize("action,risk", [
    (ActionType.EXECUTE.value, RiskLevel.LOW.value),    # skulle blivit PERMIT
    (ActionType.COMMIT.value, RiskLevel.LOW.value),     # owner-mandatory
    (ActionType.EXECUTE.value, RiskLevel.HIGH.value),   # over risktaket
])
def test_non_audit_backend_failure_is_still_a_verdict(action, risk):
    """Ett OSError fran auditbackenden ska bli ett verdikt, inte ett undantag."""
    mediator, agent_key, _owner, _audit, _tmp = build()
    mediator._audit = ExplodingAudit()

    decision = mediator.evaluate(request(
        agent_key, action_type=action, domain="code",
        risk_level=risk, payload={"file": "a.py"},
    ))

    assert decision.verdict in (Verdict.DENY, Verdict.ESCALATE)
    assert decision.grant is None
    # Utan detta vore testet tomt: det skulle passera aven om ingangen aldrig
    # kom fram till auditskrivningen och darmed aldrig provade natet.
    assert "audit.write_failed" in decision.applied_rules
    assert "audit.write_failed" in decision.applied_rules


def test_would_be_permit_is_downgraded_to_deny():
    """Det som skulle blivit PERMIT nedgraderas -- en oskriven logg ar inget lov."""
    mediator, agent_key, _owner, _audit, _tmp = build()
    mediator._audit = ExplodingAudit()
    decision = mediator.evaluate(request(
        agent_key, action_type=ActionType.EXECUTE.value, domain="code",
        risk_level=RiskLevel.LOW.value, payload={"file": "a.py"},
    ))
    assert decision.verdict is Verdict.DENY


def test_failure_never_yields_a_permission():
    """Det starkare pastaendet: inget fel far ge PERMIT."""
    mediator, agent_key, _owner, _audit, _tmp = build()
    mediator._audit = ExplodingAudit()
    decision = mediator.evaluate(request(
        agent_key, action_type=ActionType.EXECUTE.value, domain="code",
        risk_level=RiskLevel.LOW.value, payload={"file": "a.py"},
    ))
    assert decision.verdict is not Verdict.PERMIT


class _OddPrincipal:
    """Duck-typad principal som saknar .principal_id."""


class BrokenAuthenticator:
    """Injicerad authenticator som lamnar ett principal-objekt kernan inte forstar.

    Authenticator ar precis som audit ett injicerat beroende: konstruktorn tar
    emot vilket objekt som helst med .authenticate(). Det som kommer tillbaka
    behover alltsa inte vara en Principal.
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
    """Canon vars payload-hash fallerar -- samma klass av fel, annan rad."""

    def __init__(self, inner):
        self._inner = inner

    def get(self, key, default=None):
        return self._inner.get(key, default)

    def full_payload_hash(self):
        raise RuntimeError("hash backend unavailable")

    def __getattr__(self, name):
        return getattr(self._inner, name)


def test_unusable_principal_is_a_verdict_not_an_exception():
    """Buggen: _finish byggde auditposten FORE sitt try -- undantaget slapp ut.

    _finish ar sista natet: bade _gated:s fallback och varje normal utgang gar
    genom den. Laste den `principal.principal_id` pa ett objekt utan det
    attributet kom AttributeError ut ur evaluate() i stallet for ett verdikt.
    """
    mediator, agent_key, _owner, _audit, _tmp = build()
    mediator._authn = BrokenAuthenticator(mediator._authn)

    decision = mediator.evaluate(request(
        agent_key, action_type=ActionType.EXECUTE.value,
        domain="code", risk_level=RiskLevel.LOW.value))

    # Vilken gren som fangar spelar ingen roll -- kravet ar att evaluate()
    # lamnar ett verdikt och ingen behorighet. Har fangas felet redan i
    # _gated:s fallback, och _finish klarar da av att beskriva det som None.
    assert decision.verdict is Verdict.DENY
    assert decision.grant is None
    assert decision.bound_principal is None


def test_payload_hash_failure_is_a_verdict_not_an_exception():
    """Samma nat, annan rad i samma dict: full_payload_hash() kastar."""
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
    """Granskningsfynd 2026-09-10: bara evaluate() var tackt.

    Alla sju ingangar gar genom _gated och _finish, men det var ett pastaende
    om koden -- inte nagot som foll om det slutade galla. Med en auditbackend
    som kastar ska var och en av dem lamna ett verdikt, aldrig ett undantag.
    """
    mediator, agent_key, _owner, _audit, _tmp = build()
    mediator._audit = ExplodingAudit()

    decision = getattr(mediator, method)(request(
        agent_key, action_type=ActionType.EXECUTE.value,
        domain="code", risk_level=RiskLevel.LOW.value))

    assert decision.verdict in (Verdict.DENY, Verdict.ESCALATE)
    assert decision.grant is None
    # Utan detta vore testet tomt: det skulle passera aven om ingangen aldrig
    # kom fram till auditskrivningen och darmed aldrig provade natet.
    assert "audit.write_failed" in decision.applied_rules
