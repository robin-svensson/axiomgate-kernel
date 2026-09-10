#!/usr/bin/env python3
"""Dumpa det publika API:t direkt ur det installerade paketet.

docs/API.md ska stämma med utdata härifrån. Skriv aldrig av en signatur
för hand — kör detta och jämför.
"""
import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import axiomgate_kernel  # noqa: E402

TARGETS = [
    "Mediator", "MediatorClient", "AuditLog", "EvidenceJournal",
    "CapabilityRegistry", "PrincipalKeyStore", "ReservedGrantStore",
    "EscalationStore", "PolicySnapshot", "Decision", "ReservedGrant",
]


def main() -> int:
    print(f"# Publikt API — {len(axiomgate_kernel.__all__)} namn i __all__")
    print()
    print("## Enums och konstanter")
    for name in axiomgate_kernel.__all__:
        obj = getattr(axiomgate_kernel, name)
        if inspect.isclass(obj) and issubclass(obj, __import__("enum").Enum):
            print(f"  {name}: " + ", ".join(m.value for m in obj))
    print(f"  OWNER_PRINCIPAL_ID = {axiomgate_kernel.OWNER_PRINCIPAL_ID!r}")
    print(f"  OWNER_MANDATORY_ACTIONS = {sorted(axiomgate_kernel.OWNER_MANDATORY_ACTIONS)}")
    print()
    print("## Klasser")
    for target in TARGETS:
        obj = getattr(axiomgate_kernel, target, None)
        if obj is None:
            print(f"### {target}  (SAKNAS)")
            continue
        print(f"### {target}")
        for name, member in inspect.getmembers(obj, predicate=inspect.isfunction):
            if name.startswith("_") and name != "__init__":
                continue
            sig = str(inspect.signature(member)).replace("self, ", "").replace("self", "")
            print(f"    {name}{sig}")
    print()
    # Fria funktioner dumpades inte förut, och därför kunde de handskrivna
    # raderna i API.md:s "Identity and capability" glida oupptäckt — tre av dem
    # hade gjort det när en granskare läste dokumentet 2026-09-10.
    print("## Fria funktioner")
    for name in sorted(axiomgate_kernel.__all__):
        obj = getattr(axiomgate_kernel, name)
        if inspect.isfunction(obj):
            print(f"    {name}{inspect.signature(obj)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
