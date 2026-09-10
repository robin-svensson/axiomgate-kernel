#!/usr/bin/env python3
"""Räknar fälten i en audit-post ur en skarp beslutsflöde.

README påstår hur många fält kärnan skriver per beslut, och hur många av dem
maskeringen döljer. Påståendet var sant när det skrevs och ruttnade tyst: R1
och R2 lade till `provenance`, `mandate_id`, `effective_risk_ceiling` och
`seq`, så 17 blev 21 utan att någon rörde meningen. Ett dokumentpåstående om
en siffra måste låsas mekaniskt, annars mäter det bara när det senast lästes.

Kör ett riktigt PERMIT-flöde genom Mediator — ingen mock utom provenance-
checkern, som annars kräver ett git-repo — och skriver

    falt=<n> maskerade=<n>

till stdout. `scripts/verify_claims.sh` jämför siffrorna med README.
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
            # Ett DENY skriver en annan post. Då mäter vi inte det vi påstår.
            print(f"FEL: vantade PERMIT, fick {decision.verdict} ({decision.reason})")
            return 1

        entries = audit.entries()
        if len(entries) != 1:
            print(f"FEL: vantade en post, fick {len(entries)}")
            return 1

        entry = entries[0]
        masked = [k for k, v in entry.items() if v == MASK]
        print(f"falt={len(entry)} maskerade={len(masked)}")
        return 0
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
