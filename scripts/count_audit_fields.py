#!/usr/bin/env python3
"""Count the fields in an audit entry from a real decision flow.

README claims how many fields the kernel writes per decision, and how many
of those the masking hides. The claim was true when written and rotted
silently: R1 and R2 added `provenance`, `mandate_id`, `effective_risk_ceiling`
and `seq`, so 17 became 21 without anyone touching the sentence. A document
claim about a number must be locked down mechanically, otherwise it only
measures what was true when it was last read.

Runs a real PERMIT flow through Mediator -- no mock except the provenance
checker, which would otherwise require a git repo -- and writes

    fields=<n> masked=<n>

to stdout. `scripts/verify_claims.sh` compares the numbers with README.
"""
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "examples"))

from _setup import build, request  # noqa: E402

from axiomgate_kernel import Verdict  # noqa: E402

MASK = "***"


def main() -> int:
    mediator, agent_key, _owner_key, audit, tmpdir = build()
    try:
        decision = mediator.evaluate(request(
            agent_key,
            action_type="INSPECT",
            domain="code",
            risk_level="LOW",
            payload={"path": "README.md"},
        ))
        if decision.verdict is not Verdict.PERMIT:
            # A DENY writes a different entry. Then we are not measuring what we claim.
            print(f"ERROR: expected PERMIT, got {decision.verdict} ({decision.reason})")
            return 1

        entries = audit.entries()
        if len(entries) != 1:
            print(f"ERROR: expected one entry, got {len(entries)}")
            return 1

        entry = entries[0]
        masked = [k for k, v in entry.items() if v == MASK]
        print(f"fields={len(entry)} masked={len(masked)}")
        return 0
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
