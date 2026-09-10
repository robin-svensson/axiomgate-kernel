#!/usr/bin/env python3
"""Mutation test of R1: remove the provenance ceiling in memory and see what happens.

On the same terms as the four existing safeguards (README, 2026-09-09): each
check is stripped out in memory, the scenario is rerun, and the outcome is
printed. A safeguard never seen to fail has not been demonstrated.

The outcome is not always PERMIT, and where it is not, that is a result in
itself: then a second barrier exists, and the script names it. Every case
carries its EXPECTED outcome; if reality deviates from it, that is a
finding, regardless of direction. docs/TRACEABILITY.md quotes these lines.

Run: python scripts/mutate_r1.py   (exit 0 = every case came out as declared)
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
    """A call under a mandate. mandate=None => no context bound at all."""
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
    """The minimum rule struck: the capability's ceiling rules alone."""
    authorization.effective_ceiling = lambda cap_ceiling, mandate: cap_ceiling


def strike_scope():
    """Every mandate is said to cover every action."""
    from axiomgate_kernel import principal_context as pc
    everything = frozenset(ActionType)
    for key in list(pc.MANDATE_SCOPES):
        pc.MANDATE_SCOPES[key] = everything


def strike_context_gate():
    """A missing context is said to be valid -- fail-open in the first gate."""
    authorization.is_principal_valid = lambda ctx: True


CASES = [
    dict(name="the risk ceiling: the mandate 'propose' only reaches up to LOW",
         mandate="propose", action=ActionType.PROPOSE.value,
         risk=RiskLevel.MEDIUM.value,
         rule="authz.provenance_risk_ceiling",
         mutate=strike_minimum,
         expect="PERMIT", second_barrier=None),
    dict(name="the scope: the mandate 'read-only' does not reach EXECUTE",
         mandate="read-only", action=ActionType.EXECUTE.value,
         risk=RiskLevel.LOW.value,
         rule="authz.mandate_action_out_of_scope",
         mutate=strike_scope,
         expect="PERMIT", second_barrier=None),
    dict(name="a missing context is a no",
         mandate=None, action=ActionType.EXECUTE.value,
         risk=RiskLevel.LOW.value,
         rule="authz.no_principal_context",
         mutate=strike_context_gate,
         expect="DENY",
         second_barrier="the mandate block itself asks whether the context "
                        "exists, so the gate at the top can be struck without "
                        "a missing context slipping through"),
]


def main() -> int:
    failures = []
    for case in CASES:
        verdict, rules = scenario(case["mandate"], case["action"], case["risk"])
        if verdict != "DENY" or case["rule"] not in rules:
            failures.append(f"BASELINE {case['name']}: expected DENY with "
                            f"{case['rule']}, got {verdict} {rules}")
            continue
        print(f"  baseline  {case['name']}")
        print(f"            -> DENY ({case['rule']})")

        # The mutation runs in its own process so it does not contaminate the next case.
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
            failures.append(f"MUTATED {case['name']}: declared {case['expect']}, "
                            f"actual {got}")
            continue
        if case["second_barrier"]:
            print(f"            mutated -> {got}: second barrier -- "
                  f"{case['second_barrier']}")
        else:
            print(f"            mutated -> {got}: no second barrier. "
                  "The check is what holds.")

    print()
    if failures:
        for f in failures:
            print(f"FAIL  {f}")
        return 1
    without = sum(1 for c in CASES if not c["second_barrier"])
    print(f"{len(CASES)}/{len(CASES)} mutations came out as declared. "
          f"{without} of {len(CASES)} have no second barrier.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
