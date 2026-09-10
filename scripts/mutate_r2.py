#!/usr/bin/env python3
"""Mutationstest av R2: ta bort ankarskydden i minnet och se vad som hander.

Samma villkor som de fyra befintliga skydden och som scripts/mutate_r1.py:
varje kontroll plockas bort i minnet, scenariot kors om, och utfallet skrivs
ut. Ett skydd som aldrig setts falla ar inte visat.

Utfallet ar inte alltid "slapps igenom", och dar det inte ar det ar det ett
resultat i sig: da finns en andra barriar, och skriptet namnger den. Varje
fall bar sitt FORVANTADE utfall; avviker verkligheten fran det ar det ett
fynd, oavsett at vilket hall. docs/TRACEABILITY.md citerar de har raderna.

Kor: python scripts/mutate_r2.py   (exit 0 = alla fall foll ut som deklarerat)
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
    """En annan kedja med samma nyckel, lika lang. Internt helt giltig.

    Utfall: "PASS" = prefixkontrollen slapper igenom den, "BLOCK" = nekad.
    """
    log, path = _fresh(3, marker="a")
    anchor = log.head()
    os.remove(path)
    forged, _ = _fresh(3, marker="b", path=path)
    ok, _msg, _last, _count = forged.verify_prefix(*anchor)
    return "PASS" if ok else "BLOCK"


def truncated_tail():
    """Tva poster bort ur en kedja pa fem, provad mot ankaret."""
    log, path = _fresh(5)
    anchor = log.head()
    lines = open(path, encoding="utf-8").read().splitlines(True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("".join(lines[:3]))
    reopened = AuditLog(path, KEY)
    ok, _msg, _last, _count = reopened.verify_prefix(*anchor)
    return "PASS" if ok else "BLOCK"


def anchored_startup_on_truncated_log():
    """Konstruktorn far ett ankare, filen ar kapad. Oppnar den anda?"""
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
    """Hash-jamforelsen pa den ankrade positionen struken."""
    audit_module.anchor_matches = lambda at_anchor, anchor_head: True


def strike_anchor_covers():
    """Langdkontrollen struken: loggen sags alltid vara lang nog."""
    audit_module.anchor_covers = lambda count, anchor_count: True


def strike_startup_gate():
    """Konstruktorns grind struken: prefixsvaret sags alltid vara ok."""
    audit_module.AuditLog.verify_prefix = (
        lambda self, *a, **k: (True, "struken", None, 0))


CASES = [
    dict(name="en utbytt kedja far inte passera som prefix",
         probe=substituted_chain, mutate=strike_anchor_matches,
         expect="PASS", second_barrier=None),
    dict(name="en kapad svans far inte passera som prefix",
         probe=truncated_tail, mutate=strike_anchor_covers,
         expect="BLOCK",
         second_barrier="utan langdkontrollen finns ingen post pa den "
                        "ankrade positionen, sa hash-jamforelsen mot None "
                        "nekar anda -- men meddelandet sager da 'replaced' "
                        "dar 'truncated' vore sant"),
    dict(name="en ankrad konstruktor far inte oppna en kapad logg",
         probe=anchored_startup_on_truncated_log, mutate=strike_startup_gate,
         expect="PASS", second_barrier=None),
]


def main() -> int:
    failures = []
    for case in CASES:
        got = case["probe"]()
        if got != "BLOCK":
            failures.append(f"BASLINJE {case['name']}: vantade BLOCK, fick {got}")
            continue
        print(f"  baslinje  {case['name']}")
        print("            -> BLOCK")

        # Mutationen kors i en egen process sa den inte smittar nasta fall.
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
            failures.append(f"MUTERAD {case['name']}: deklarerat {case['expect']}, "
                            f"faktiskt {got}")
            continue
        if case["second_barrier"]:
            print(f"            muterad -> {got}: andra barriar -- "
                  f"{case['second_barrier']}")
        else:
            print(f"            muterad -> {got}: ingen andra barriar. "
                  "Kontrollen ar den som bar.")

    print()
    if failures:
        for f in failures:
            print(f"FAIL  {f}")
        return 1
    without = sum(1 for c in CASES if not c["second_barrier"])
    print(f"{len(CASES)}/{len(CASES)} mutationer foll ut som deklarerat. "
          f"{without} av {len(CASES)} har ingen andra barriar.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
