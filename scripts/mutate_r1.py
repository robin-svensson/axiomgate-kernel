#!/usr/bin/env python3
"""Mutationstest av R1: ta bort provenanstaket i minnet och se vad som hander.

Pa samma villkor som de fyra befintliga skydden (README, 2026-09-09): varje
kontroll plockas bort i minnet, scenariot kors om, och utfallet skrivs ut. Ett
skydd som aldrig setts falla ar inte visat.

Utfallet ar inte alltid PERMIT, och dar det inte ar det ar det ett resultat i
sig: da finns en andra barriar, och skriptet namnger den. Varje fall bar sitt
FORVANTADE utfall; avviker verkligheten fran det ar det ett fynd, oavsett at
vilket hall. docs/TRACEABILITY.md citerar de har raderna.

Kor: python scripts/mutate_r1.py   (exit 0 = alla fall foll ut som deklarerat)
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "examples"))

from _setup import build, request  # noqa: E402

from axiomgate_kernel import ActionType, RiskLevel  # noqa: E402
from axiomgate_kernel import authorization  # noqa: E402
from axiomgate_kernel.principal_context import (  # noqa: E402
    PrincipalContext, principal_context_scope,
)


def scenario(mandate, action, risk):
    """Ett anrop under ett mandat. mandate=None => ingen context alls bunden."""
    mediator, agent_key, _o, _a, _t = build()
    mediator.require_principal_context = True
    req = request(agent_key, action_type=action, domain="code",
                  risk_level=risk, payload={"file": "a.py"})
    if mandate is None:
        d = mediator.evaluate(req)
    else:
        ctx = PrincipalContext(
            principal_id="agent-a", parent_principal_id="owner",
            session_id="s1", mandate=mandate, provenance="direct")
        with principal_context_scope(ctx):
            d = mediator.evaluate(req)
    return d.verdict.value, list(d.applied_rules)


def strike_minimum():
    """Minimum-regeln struken: capabilityns tak far rada ensamt."""
    authorization.effective_ceiling = lambda cap_ceiling, mandate: cap_ceiling


def strike_scope():
    """Varje mandat sags omfatta varje action."""
    from axiomgate_kernel import principal_context as pc
    everything = frozenset(ActionType)
    for key in list(pc.MANDATE_SCOPES):
        pc.MANDATE_SCOPES[key] = everything


def strike_context_gate():
    """Ett saknat context sags vara giltigt -- fail-open i den forsta grinden."""
    authorization.is_principal_valid = lambda ctx: True


CASES = [
    dict(name="risktaket: mandatet 'propose' racker bara till LOW",
         mandate="propose", action=ActionType.PROPOSE.value,
         risk=RiskLevel.MEDIUM.value,
         rule="authz.provenance_risk_ceiling",
         mutate=strike_minimum,
         expect="PERMIT", second_barrier=None),
    dict(name="scopet: mandatet 'read-only' racker inte till EXECUTE",
         mandate="read-only", action=ActionType.EXECUTE.value,
         risk=RiskLevel.LOW.value,
         rule="authz.mandate_action_out_of_scope",
         mutate=strike_scope,
         expect="PERMIT", second_barrier=None),
    dict(name="det saknade contextet ar ett nej",
         mandate=None, action=ActionType.EXECUTE.value,
         risk=RiskLevel.LOW.value,
         rule="authz.no_principal_context",
         mutate=strike_context_gate,
         expect="DENY",
         second_barrier="mandatblocket fragar sjalvt om contexten finns, sa "
                        "grinden hogst upp kan strykas utan att ett saknat "
                        "context slipper igenom"),
]


def main() -> int:
    failures = []
    for case in CASES:
        verdict, rules = scenario(case["mandate"], case["action"], case["risk"])
        if verdict != "DENY" or case["rule"] not in rules:
            failures.append(f"BASLINJE {case['name']}: vantade DENY med "
                            f"{case['rule']}, fick {verdict} {rules}")
            continue
        print(f"  baslinje  {case['name']}")
        print(f"            -> DENY ({case['rule']})")

        # Mutationen kors i en egen process sa den inte smittar nasta fall.
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r)
            case["mutate"]()
            v, _ = scenario(case["mandate"], case["action"], case["risk"])
            os.write(w, v.encode())
            os._exit(0)
        os.close(w)
        got = os.read(r, 64).decode()
        os.close(r)
        os.waitpid(pid, 0)

        if got != case["expect"]:
            failures.append(f"MUTERAD {case['name']}: deklarerat {case['expect']}, "
                            f"faktiskt {got}")
            continue
        if case["second_barrier"]:
            print(f"            muterad -> {got}: andra barriar -- "
                  f"{case['second_barrier']}")
        else:
            print(f"            muterad -> {got}: ingen andra barriar. "
                  "Kontrollen ar den som bar.")

    print()
    if failures:
        for f in failures:
            print(f"FAIL  {f}")
        return 1
    without = sum(1 for c in CASES if not c["second_barrier"])
    print(f"{len(CASES)}/{len(CASES)} mutationer foll ut som deklarerat. "
          f"{without} av {len(CASES)} har ingen andra barriar.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
