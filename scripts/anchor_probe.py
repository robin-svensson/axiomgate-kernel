#!/usr/bin/env python3
"""Kor de pastaenden docs/ANCHORING.md gor, och skriv ut svaren.

Dokumentet citerar utdata harifran ordagrant. Andras beteendet ska citaten
sluta stamma -- verify_claims.sh kraver att raderna finns kvar i bada.
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

    # Kapa svansen: tva poster bort ur en kedja pa fyra.
    lines = open(path, encoding="utf-8").read().splitlines(True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("".join(lines[:2]))

    # Konstruktionen klagar inte -- en kapad kedja ar internt konsistent.
    cut = AuditLog(path, key)

    ok, msg, _ = cut.verify_chain()
    print(f"kapad, ingen anchor -> ({ok}, {msg!r}, '{cut.head()[0][:8]}…')")
    for label, args in (
        ("kapad, med anchor", (head_hash, count)),
        ("bara count", (None, count)),
        ("bara head", (head_hash, None)),
    ):
        ok, msg, _ = cut.verify_chain(*args)
        print(f"{label} -> ({ok}, {msg!r})")

    # En anchor tagen tidigare an loggens nuvarande lange.
    fresh = AuditLog(os.path.join(tmp, "b.log"), key)
    for i in range(3):
        fresh.append({"n": i})
    stale_head, stale_count = fresh.head()
    fresh.append({"n": 3})
    ok, msg, _ = fresh.verify_chain(stale_head, stale_count)
    print(f"stale anchor -> ({ok}, {msg!r})")

    # Samma gamla anchor, samma vaxta logg -- men prefixfragan i stallet.
    ok, msg, _last, _count = fresh.verify_prefix(stale_head, stale_count)
    print(f"stale anchor, prefix -> ({ok}, {msg!r})")

    # Prefixfragan pa den kapade loggen: fortfarande ett nej.
    ok, msg, _last, _count = cut.verify_prefix(head_hash, count)
    print(f"kapad, prefix -> ({ok}, {msg!r})")

    # En kedja som bytts ut mot en egentillverkad, lika lang och internt
    # giltig. Den exakta kontrollen ser bara "head mismatch"; prefixfragan
    # sager vad som faktiskt hant.
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
    print(f"utbytt kedja, prefix -> ({ok}, {msg!r})")

    # Ett halvt anchor ar inget anchor.
    ok, msg, _last, _count = fresh.verify_prefix(stale_head, None)
    print(f"halvt anchor, prefix -> ({ok}, {msg!r})")

    # Ett ogiltigt anchor_count ar ett anropsfel, inte ett fynd.
    ok, msg, _last, _count = fresh.verify_prefix(stale_head, 0)
    print(f"noll count med head, prefix -> ({ok}, {msg!r})")

    # Och samma fraga stalld redan vid oppningen.
    try:
        AuditLog(path, key, anchor=(head_hash, count))
        print("ankrad konstruktor pa kapad logg -> oppnade")
    except AuditError as exc:
        print(f"ankrad konstruktor pa kapad logg -> AuditError: {exc}")
    grown = AuditLog(os.path.join(tmp, "b.log"), key, anchor=(stale_head, stale_count))
    print(f"ankrad konstruktor pa vaxt logg -> oppnade, {grown.head()[1]} poster")


if __name__ == "__main__":
    main()
