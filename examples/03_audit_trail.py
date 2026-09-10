"""Example 3 — TRACE: the audit chain is append-only and tamper-evident.

Run:  python examples/03_audit_trail.py
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from examples._setup import build, request

mediator, agent_key, owner_key, audit, tmpdir = build()

for domain in ("code", "finance", "code"):
    mediator.evaluate(request(agent_key, action_type="EXECUTE",
                              domain=domain, risk_level="MEDIUM"))

ok, msg, _ = audit.verify_chain()
print("entries      :", sum(1 for _ in open(audit.path)))
print("chain intact :", ok, "-", msg)
assert ok

# Now rewrite one entry the way an attacker covering their tracks would:
# flip the denied request into an allowed one, in place.
lines = open(audit.path).read().splitlines()
target = next(i for i, l in enumerate(lines) if '"finance"' in l)
lines[target] = lines[target].replace('"finance"', '"code"')
open(audit.path, "w").write("\n".join(lines) + "\n")

ok, msg, bad = audit.verify_chain()
print("\nafter tampering with entry index", target, "(0-based)")
print("chain intact :", ok, "-", msg)
assert not ok, "tampering went undetected"

# The point: the HMAC chain does not prevent the edit — it makes the edit
# impossible to hide. That is what an EU AI Act Art. 12 record has to do.
print("\nOK — the forgery is detected, and the log names where.")
