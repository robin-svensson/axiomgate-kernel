#!/usr/bin/env python3
"""Mutation test of R2: remove the anchor safeguards in memory and see what happens.

Same terms as the four existing safeguards and as scripts/mutate_r1.py: each
check is stripped out in memory, the scenario is rerun, and the outcome is
printed. A safeguard never seen to fail has not been demonstrated.

The outcome is not always "let through", and where it is not, that is a
result in itself: then a second barrier exists, and the script names it.
Every case carries its EXPECTED outcome; if reality deviates from it, that
is a finding, regardless of direction. docs/TRACEABILITY.md quotes these
lines.

Run: python scripts/mutate_r2.py   (exit 0 = every case came out as declared)
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from axiomgate_kernel import AuditLog, AuditError, generate_key  # noqa: E402
from axiomgate_kernel import audit as audit_module  # noqa: E402

KEY = generate_key()


def _fresh(n, marker="a", path=None):
    if path is None:
        path = os.path.join(tempfile.mkdtemp(prefix="axiomgate-kernel-mut-r2-"), "audit.log")
    log = AuditLog(path, KEY)
    for i in range(n):
        log.append({"marker": marker, "n": i})
    return log, path


def substituted_chain():
    """A different chain with the same key, the same length. Internally fully valid.

    Outcome: "PASS" = the prefix check lets it through, "BLOCK" = refused.
    """
    log, path = _fresh(3, marker="a")
    anchor = log.head()
    os.remove(path)
    forged, _ = _fresh(3, marker="b", path=path)
    ok, _msg, _last, _count = forged.verify_prefix(*anchor)
    return "PASS" if ok else "BLOCK"


def truncated_tail():
    """Two entries removed from a chain of five, checked against the anchor."""
    log, path = _fresh(5)
    anchor = log.head()
    lines = open(path, encoding="utf-8").read().splitlines(True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("".join(lines[:3]))
    reopened = AuditLog(path, KEY)
    ok, _msg, _last, _count = reopened.verify_prefix(*anchor)
    return "PASS" if ok else "BLOCK"


def anchored_startup_on_truncated_log():
    """The constructor gets an anchor, the file is truncated. Does it open anyway?"""
    log, path = _fresh(5)
    anchor = log.head()
    lines = open(path, encoding="utf-8").read().splitlines(True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("".join(lines[:3]))
    try:
        AuditLog(path, KEY, anchor=anchor)
    except AuditError:
        return "BLOCK"
    return "PASS"


def strike_anchor_matches():
    """The hash comparison at the anchored position struck."""
    audit_module.anchor_matches = lambda at_anchor, anchor_head: True


def strike_anchor_covers():
    """The length check struck: the log is said to always be long enough."""
    audit_module.anchor_covers = lambda count, anchor_count: True


def strike_startup_gate():
    """The constructor's gate struck: the prefix answer is said to always be ok."""
    audit_module.AuditLog.verify_prefix = (
        lambda self, *a, **k: (True, "struck", None, 0))


CASES = [
    dict(name="a substituted chain must not pass as a prefix",
         probe=substituted_chain, mutate=strike_anchor_matches,
         expect="PASS", second_barrier=None),
    dict(name="a truncated tail must not pass as a prefix",
         probe=truncated_tail, mutate=strike_anchor_covers,
         expect="BLOCK",
         second_barrier="without the length check there is no entry at the "
                        "anchored position, so the hash comparison against "
                        "None still refuses -- but the message then says "
                        "'replaced' where 'truncated' would be true"),
    dict(name="an anchored constructor must not open a truncated log",
         probe=anchored_startup_on_truncated_log, mutate=strike_startup_gate,
         expect="PASS", second_barrier=None),
]


def main() -> int:
    failures = []
    for case in CASES:
        got = case["probe"]()
        if got != "BLOCK":
            failures.append(f"BASELINE {case['name']}: expected BLOCK, got {got}")
            continue
        print(f"  baseline  {case['name']}")
        print("            -> BLOCK")

        # The mutation runs in its own process so it does not contaminate the next case.
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r)
            case["mutate"]()
            os.write(w, case["probe"]().encode())
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
