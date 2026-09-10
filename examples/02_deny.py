"""Example 2 — REFUSAL: the agent asks for what it may not have.

Three ways an ask is refused. Note that they are not all DENY: exceeding the
risk ceiling produces ESCALATE, which blocks the action and opens an owner
decision instead of simply rejecting it. Both outcomes share the property
that matters — nothing is executed.

Run:  python examples/02_deny.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from examples._setup import build, request
from axiomgate_kernel import Verdict

mediator, agent_key, owner_key, audit, tmpdir = build()

cases = [
    ("outside its domain",     dict(action_type="EXECUTE", domain="finance", risk_level="MEDIUM")),
    ("above its risk ceiling", dict(action_type="EXECUTE", domain="code",    risk_level="HIGH")),
    ("forged signature",       dict(action_type="EXECUTE", domain="code",    risk_level="MEDIUM")),
]

for label, fields in cases:
    key = owner_key if label == "forged signature" else agent_key
    req = request(key, **fields)
    if label == "forged signature":
        req["principal_id"] = req["agent_id"] = "agent-a"  # signed by the wrong key
    decision = mediator.evaluate(req)
    print(f"{label:24} -> {decision.verdict.value:8} ({decision.applied_rules[-1]})")
    assert decision.verdict is not Verdict.PERMIT, (label, decision.verdict)

# The point: every refusal is a decision with a reason, not an exception the
# caller can swallow. Nothing reached an executor.
print("\nOK — three refusals, three recorded reasons, zero actions taken.")
print("   (HIGH risk escalates rather than denies — the owner still has to answer.)")
