#!/usr/bin/env python3
"""Run the claims docs/ANCHORING.md makes, and print the answers.

The document quotes this output verbatim. If the behavior changes, the
quotes should stop matching -- verify_claims.sh requires the lines to stay
present in both.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from axiomgate_kernel import AuditError, AuditLog, generate_key  # noqa: E402


def main() -> None:
    tmp = tempfile.mkdtemp(prefix="axiomgate-kernel-anchor-")
    path = os.path.join(tmp, "audit.log")
    key = generate_key()

    log = AuditLog(path, key)
    for i in range(4):
        log.append({"n": i})
    head_hash, count = log.head()

    # Truncate the tail: two entries removed from a chain of four.
    lines = open(path, encoding="utf-8").read().splitlines(True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("".join(lines[:2]))

    # Construction does not complain -- a truncated chain is internally consistent.
    cut = AuditLog(path, key)

    ok, msg, _ = cut.verify_chain()
    print(f"truncated, no anchor -> ({ok}, {msg!r}, '{cut.head()[0][:8]}...')")
    for label, args in (
        ("truncated, with anchor", (head_hash, count)),
        ("count only", (None, count)),
        ("head only", (head_hash, None)),
    ):
        ok, msg, _ = cut.verify_chain(*args)
        print(f"{label} -> ({ok}, {msg!r})")

    # An anchor taken earlier than the log's current length.
    fresh = AuditLog(os.path.join(tmp, "b.log"), key)
    for i in range(3):
        fresh.append({"n": i})
    stale_head, stale_count = fresh.head()
    fresh.append({"n": 3})
    ok, msg, _ = fresh.verify_chain(stale_head, stale_count)
    print(f"stale anchor -> ({ok}, {msg!r})")

    # The same stale anchor, the same grown log -- but the prefix question instead.
    ok, msg, _last, _count = fresh.verify_prefix(stale_head, stale_count)
    print(f"stale anchor, prefix -> ({ok}, {msg!r})")

    # The prefix question on the truncated log: still a no.
    ok, msg, _last, _count = cut.verify_prefix(head_hash, count)
    print(f"truncated, prefix -> ({ok}, {msg!r})")

    # A chain swapped out for a self-made one, equally long and internally
    # valid. The exact check only sees "head mismatch"; the prefix question
    # says what actually happened.
    sub_path = os.path.join(tmp, "c.log")
    original = AuditLog(sub_path, key)
    for i in range(3):
        original.append({"branch": "a", "n": i})
    sub_head, sub_count = original.head()
    os.remove(sub_path)
    forged = AuditLog(sub_path, key)
    for i in range(3):
        forged.append({"branch": "b", "n": i})
    ok, msg, _last, _count = forged.verify_prefix(sub_head, sub_count)
    print(f"substituted chain, prefix -> ({ok}, {msg!r})")

    # Half an anchor is no anchor.
    ok, msg, _last, _count = fresh.verify_prefix(stale_head, None)
    print(f"half anchor, prefix -> ({ok}, {msg!r})")

    # An invalid anchor_count is a call error, not a finding.
    ok, msg, _last, _count = fresh.verify_prefix(stale_head, 0)
    print(f"zero count with head, prefix -> ({ok}, {msg!r})")

    # And the same question asked already at open time.
    try:
        AuditLog(path, key, anchor=(head_hash, count))
        print("anchored constructor on truncated log -> opened")
    except AuditError as exc:
        print(f"anchored constructor on truncated log -> AuditError: {exc}")
    grown = AuditLog(os.path.join(tmp, "b.log"), key, anchor=(stale_head, stale_count))
    print(f"anchored constructor on grown log -> opened, {grown.head()[1]} entries")


if __name__ == "__main__":
    main()
