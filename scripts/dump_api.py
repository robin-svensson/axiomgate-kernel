#!/usr/bin/env python3
"""Dump the public API straight from the installed package.

docs/API.md should match the output from here. Never hand-copy a
signature -- run this and compare.
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
    print(f"# Public API -- {len(axiomgate_kernel.__all__)} names in __all__")
    print()
    print("## Enums and constants")
    for name in axiomgate_kernel.__all__:
        obj = getattr(axiomgate_kernel, name)
        if inspect.isclass(obj) and issubclass(obj, __import__("enum").Enum):
            print(f"  {name}: " + ", ".join(m.value for m in obj))
    print(f"  OWNER_PRINCIPAL_ID = {axiomgate_kernel.OWNER_PRINCIPAL_ID!r}")
    print(f"  OWNER_MANDATORY_ACTIONS = {sorted(axiomgate_kernel.OWNER_MANDATORY_ACTIONS)}")
    print()
    print("## Classes")
    for target in TARGETS:
        obj = getattr(axiomgate_kernel, target, None)
        if obj is None:
            print(f"### {target}  (MISSING)")
            continue
        print(f"### {target}")
        for name, member in inspect.getmembers(obj, predicate=inspect.isfunction):
            if name.startswith("_") and name != "__init__":
                continue
            sig = str(inspect.signature(member)).replace("self, ", "").replace("self", "")
            print(f"    {name}{sig}")
    print()
    # Free functions were not dumped before, and so the handwritten lines in
    # API.md's "Identity and capability" section could drift undetected --
    # three of them had when a reviewer read the document on 2026-09-10.
    print("## Free functions")
    for name in sorted(axiomgate_kernel.__all__):
        obj = getattr(axiomgate_kernel, name)
        if inspect.isfunction(obj):
            print(f"    {name}{inspect.signature(obj)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
