"""Example 1 — PERMIT: the agent asks for something it is allowed to do.

Run:  python examples/01_permit.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from examples._setup import build, request
from axiomgate_kernel import Verdict

mediator, agent_key, owner_key, audit, tmpdir = build()

# EXECUTE in the "code" domain at MEDIUM risk is inside cap-a.
decision = mediator.evaluate(request(
    agent_key, action_type="EXECUTE", domain="code", risk_level="MEDIUM",
))

print("verdict      :", decision.verdict.value)
print("applied rules:", ", ".join(decision.applied_rules))
print("grant issued :", decision.grant is not None)
print("audit hash   :", (decision.audit_hash or "")[:16], "...")

assert decision.verdict is Verdict.PERMIT, decision.verdict

# The point: the agent did not act. It received permission to act, recorded
# in a chained audit entry. Execution is the caller's job, and the kernel
# never performs it.
ok, msg, _ = audit.verify_chain()
print("chain intact :", ok, "-", msg)
assert ok
print("\nOK — permission granted, and the grant is on the record.")
