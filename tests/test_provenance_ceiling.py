"""R1: provenansen bounder auktoriteten, inte bara capabilityn.

Fram till 2026-09-10 var principal_context.py doktrin utan verkan. Modulen
definierade mandat, tak per mandat och monoton propagering till subagenter --
och inget verdikt las den. En agent med ett capability upp till MEDIUM fick
gora MEDIUM aven nar det mandat den arbetade under bara racker till LOW.

Kravet ur docs/ROADMAP.md R1: effektivt tak = min(capability.risk_ceiling,
mandatets tak), contexten laest fran en bunden PrincipalContext, och ett
SAKNAT context failar closed -- aldrig ett fallback till det mest tillatande.
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
    """En mediator som kraver en bunden context. Samma bygge i ovrigt."""
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
    """Ingen bunden context far aldrig betyda 'inget tak'.

    Det ar hela skillnaden mellan fail-closed och fail-open: en integrator som
    glommer att satta contexten ska stoppas, inte tyst fa den vidaste ramen.
    """
    mediator, agent_key, _o, _a, _t = strict()
    decision = execute(mediator, agent_key, RiskLevel.LOW.value)
    assert decision.verdict is Verdict.DENY
    assert "authz.no_principal_context" in decision.applied_rules
    assert decision.grant is None


def test_context_without_mandate_is_denied():
    """Ett context utan mandat bar ingen ram. Modulen sager sjalv: must escalate."""
    mediator, agent_key, _o, _a, _t = strict()
    with principal_context_scope(ctx(None)):
        decision = execute(mediator, agent_key, RiskLevel.LOW.value)
    assert decision.verdict is Verdict.DENY
    assert "authz.no_mandate" in decision.applied_rules


def test_unparseable_mandate_is_denied():
    """En mandatstrang som inte gar att tolka ar inte ett tomt mandat."""
    mediator, agent_key, _o, _a, _t = strict()
    with principal_context_scope(ctx("execute:expires:inte-ett-datum")):
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
    """Capabilityn racker till MEDIUM, mandatet 'propose' bara till LOW.

    PROPOSE ligger inom bada scopen -- det ar alltsa uteslutande RISKTAKET som
    skiljer dem, vilket ar det testet ska prova. Utan R1 gav detta PERMIT:
    capabilityn var det enda som raknades.
    """
    mediator, agent_key, _o, _a, _t = strict()
    with principal_context_scope(ctx("propose")):
        decision = execute(mediator, agent_key, RiskLevel.MEDIUM.value,
                           action=ActionType.PROPOSE.value)
    assert decision.verdict is Verdict.DENY
    assert "authz.provenance_risk_ceiling" in decision.applied_rules
    # Inte capabilityns eget tak -- det klarade MEDIUM.
    assert "authz.risk_ceiling" not in decision.applied_rules


def test_capability_still_binds_below_the_mandate():
    """Taket ar ett minimum av tva, inte en ersattning av det ena.

    Mandatet 'full' racker till HIGH, capabilityn bara till MEDIUM. HIGH ar
    dessutom owner-mandatory, sa utfallet ar en eskalering -- inte ett lov.
    """
    mediator, agent_key, _o, _a, _t = strict()
    with principal_context_scope(ctx("full")):
        decision = execute(mediator, agent_key, RiskLevel.HIGH.value)
    assert decision.verdict is not Verdict.PERMIT
    assert decision.grant is None


def test_action_outside_the_mandate_is_denied():
    """Mandatet 'read-only' racker inte till EXECUTE, hur capabilityn an ser ut."""
    mediator, agent_key, _o, _a, _t = strict()
    with principal_context_scope(ctx("read-only")):
        decision = execute(mediator, agent_key, RiskLevel.LOW.value)
    assert decision.verdict is Verdict.DENY
    assert "authz.mandate_action_out_of_scope" in decision.applied_rules


def test_within_both_ceilings_still_permits():
    """Kontrollen far inte vara ett generellt nej. 'execute' + LOW gar igenom."""
    mediator, agent_key, _o, _a, _t = strict()
    with principal_context_scope(ctx("execute")):
        decision = execute(mediator, agent_key, RiskLevel.LOW.value)
    assert decision.verdict is Verdict.PERMIT
    assert decision.grant is not None


# --- Auditen --------------------------------------------------------------

def test_the_audit_record_says_which_bound_applied():
    """En lasare ska kunna se vilket tak som gallde, inte bara utfallet.

    ROADMAP R1 villkor 2: provenansen och det effektiva taket skrivs in.
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
    """Det som nekades for att contexten saknades ska ga att se i loggen."""
    mediator, agent_key, _o, audit, _t = strict()
    execute(mediator, agent_key, RiskLevel.LOW.value)
    entry = audit.entries()[-1]
    assert entry["provenance"] is None
    assert entry["mandate_id"] is None


# --- Bakatkompatibilitet ---------------------------------------------------

def test_the_default_mediator_is_unchanged():
    """Flaggan ar av som standard: befintliga integratorer ser ingen skillnad.

    Detta ar ett medvetet avsteg och det star utskrivet i ROADMAP R1 -- utan
    flaggan finns inget provenanstak alls, och det ar en kand lucka, inte ett
    smyghal.
    """
    mediator, agent_key, _o, _a, _t = build()
    assert mediator.require_principal_context is False
    decision = execute(mediator, agent_key, RiskLevel.MEDIUM.value)
    assert decision.verdict is Verdict.PERMIT


def test_the_flag_can_be_set_at_construction():
    """Den ska ga att satta dar mediatorn byggs, inte bara efterat."""
    from axiomgate_kernel import Mediator
    import inspect
    sig = inspect.signature(Mediator.__init__)
    assert "require_principal_context" in sig.parameters
    assert sig.parameters["require_principal_context"].default is False


# --- Auditposten beskriver den ram som faktiskt gallde ----------------------

def test_a_swapped_context_cannot_rewrite_the_audit_record():
    """Loggen pastod fel mandat om provenance-backenden bytte context under tiden.

    Fram till 2026-09-10 las _audit_record om den bundna contexten i stallet
    for att bara med sig den CapabilityCheck som avgjort. Mellan de tva
    raderna kor self._provenance.check() -- en INJICERAD beroende, samma
    fortroendeniva som audit och authenticator. En backend som byter ut
    contexten dar fick beslutet raknat pa ett mandat och loggat pa ett annat,
    och en granskare kunde inte se vilken ram som gav tillstandet.
    """
    from axiomgate_kernel.provenance import ProvenanceKind, ProvenanceResult

    mediator, agent_key, _o, audit, _t = strict()

    class SwapsTheContext:
        """En provenance-backend som byter mandat mitt i beslutet."""

        def check(self):
            set_principal_context(ctx("read-only", provenance="delegated"))
            return ProvenanceResult(ProvenanceKind.MATCH, "ok")

    mediator._provenance = SwapsTheContext()

    with principal_context_scope(ctx("full", provenance="direct")):
        decision = execute(mediator, agent_key, RiskLevel.MEDIUM.value,
                           action=ActionType.PROPOSE.value)

    assert decision.verdict is Verdict.PERMIT
    entry = audit.entries()[-1]
    # Beslutet rakandes under "full"/direct. Loggen ska saga samma sak.
    assert entry["provenance"] == "direct"
    assert entry["mandate_id"].startswith("mandate-full-")
    assert entry["effective_risk_ceiling"] == "MEDIUM"


# --- Samma krav pa reentry-vagen -------------------------------------------

def strict_high():
    """Som strict(), men agentens capability racker till HIGH.

    HIGH ar owner-mandatory: evaluate ger ESCALATE, owner reserverar, och
    reenter ar da den enda vagen till PERMIT. Med MEDIUM-taket i build()
    dor reentryn pa authz.risk_ceiling och PERMIT-vagen provas aldrig.
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
    """Kor hela cykeln evaluate -> decide_escalation -> reenter under mandat "full".

    Samma request_id och payload i badge stegen: den reserverade granten
    binder bada, sa en ny request_id skulle avvisas av consume_if_valid.
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
    """Reentry-PERMIT loggade None pa alla tre ramfalten -- utan nagon attack.

    frame tradades bara genom _evaluate_authenticated. I
    _reenter_authenticated satt frame=check enbart pa DENY-grenen direkt
    efter check_capability; PERMIT-vagen langre ner anropade _permit utan
    frame. Checken KORDES och satte ramen -- posten bara tappade den, sa en
    granskare av ett reentry-beslut kunde inte se vilket mandat som gallde.
    """
    mediator, agent_key, owner_key, audit, _t = strict_high()

    decision = reserve_then_reenter(mediator, agent_key, owner_key)

    assert decision.verdict is Verdict.PERMIT, decision.applied_rules
    entry = audit.entries()[-1]
    assert entry["provenance"] == "direct"
    assert entry["mandate_id"].startswith("mandate-full-")
    assert entry["effective_risk_ceiling"] == "HIGH"


def test_a_swapped_context_cannot_rewrite_the_reentry_audit_record():
    """Samma attack som pa evaluate-vagen, men mot reentryn.

    check_capability kor fore self._provenance.check() aven har, sa en
    backend som byter context daremellan far inte flytta ramen i loggen.
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
    """Aven en DENY nedstroms checken ska beskriva ramen den domdes under.

    provenance.mismatch ligger efter check_capability: ramen ar raknad, det
    ar provenansen som inte haller. Posten sa None pa alla tre ramfalten dar
    ocksa. (En DENY UPPSTROMS checken -- t.ex. reentry.already_resolved --
    ska daremot fortsatta saga None: ingen ram raknades.)
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
    """Motprovet: uppstroms checken finns ingen ram, och da ska den vara None.

    Att tacka hal med "skriv nagot" ar samma fel som att skriva 0 for ett
    saknat varde. reentry.already_resolved domer innan check_capability kors.
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
    """Nekas handlingen pa scope har inget tak provats -- da far inget stå dar.

    Fyndet 2026-09-10, samma familj som den falska sparbarheten: nar
    'authz.mandate_action_out_of_scope' fallde skrev loggen CAPABILITYNS eget
    tak i effective_risk_ceiling ('MEDIUM'), for att `ceiling` an inte hade
    rakats om via effective_ceiling(). Posten pastod alltsa att MEDIUM var den
    ram som gallde. Ingen ram gallde: beslutet togs innan nagon takjamforelse,
    och mandatets eget tak kom aldrig in i bilden. Ett saknat varde ar inte ett
    tak.
    """
    mediator, agent_key, _o, audit, _t = strict()
    with principal_context_scope(ctx("read-only")):
        decision = execute(mediator, agent_key, RiskLevel.LOW.value)
    assert decision.verdict is Verdict.DENY
    assert "authz.mandate_action_out_of_scope" in decision.applied_rules
    entry = audit.entries()[-1]
    assert entry["effective_risk_ceiling"] is None
    # Mandatet ar daremot kant och ska sta kvar: en lasare maste kunna se
    # VILKET mandat som inte rackte till.
    assert entry["mandate_id"].startswith("mandate-read-only-")
    assert entry["provenance"] == "direct"


def test_an_expired_mandate_logs_no_effective_ceiling():
    """Ett ogiltigt mandat bounder ingenting -- inte ens till sitt eget tak."""
    mediator, agent_key, _o, audit, _t = strict()
    with principal_context_scope(ctx("execute:expires:2020-01-01T00:00:00Z")):
        decision = execute(mediator, agent_key, RiskLevel.LOW.value)
    assert decision.verdict is Verdict.DENY
    assert "authz.mandate_invalid" in decision.applied_rules
    entry = audit.entries()[-1]
    assert entry["effective_risk_ceiling"] is None
    assert entry["mandate_id"].startswith("mandate-execute-")


def test_the_ceiling_that_did_apply_is_still_written():
    """Motprov: nar taket VERKLIGEN bound beslutet ska det inte bli None.

    Utan detta kunde fixen ovan vara ett generellt None och testerna anda
    passera.
    """
    mediator, agent_key, _o, audit, _t = strict()
    with principal_context_scope(ctx("propose")):
        decision = execute(mediator, agent_key, RiskLevel.MEDIUM.value,
                           action=ActionType.PROPOSE.value)
    assert "authz.provenance_risk_ceiling" in decision.applied_rules
    assert audit.entries()[-1]["effective_risk_ceiling"] == "LOW"


def test_without_the_flag_no_effective_ceiling_is_claimed():
    """Kravs ingen context finns inget effektivt tak -- docstringen sa det redan.

    CapabilityCheck-docstringen har hela tiden pastatt att
    `effective_risk_ceiling` ar None nar ingen context kravdes. Koden skrev
    anda in capabilityns eget tak ('MEDIUM'), i det lage dar det per definition
    inte finns nagon provenansram att rakna fram. Dokumentationen var ratt och
    koden fel, inte tvartom.
    """
    mediator, agent_key, _o, audit, _t = build()[:5]
    assert mediator.require_principal_context is False
    decision = execute(mediator, agent_key, RiskLevel.LOW.value)
    assert decision.verdict is Verdict.PERMIT
    entry = audit.entries()[-1]
    assert entry["effective_risk_ceiling"] is None
    assert entry["mandate_id"] is None
