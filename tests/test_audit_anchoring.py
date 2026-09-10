"""R2: ett ankare ska kunna provas mot en logg som fortfarande vaxer.

verify_chain svarar bara pa "ar detta exakt loggen jag ankrade?". Den fragan
gar inte att stalla om en levande logg: nasta post gor svaret nej, och
meddelandet "log longer than anchor" ar inte ett fynd utan bara att tiden
gatt. Darfor kunde en ankrad kontroll i praktiken bara koras mot ett stillsatt
arkiv -- och gjordes darfor sallan eller aldrig.

Den har filen provar den andra fragan: BORJAR loggen med den kedja jag
ankrade? Och den provar att svaret gar att krava redan nar loggen oppnas,
vilket ar det enda tillfalle en kapad svans annars aldrig upptacks:
AuditLog(path, key) replayar en avhuggen kedja utan att klaga, eftersom en
avhuggen kedja ar internt konsistent.
"""

import os
import tempfile

import pytest

from axiomgate_kernel import AuditLog, AuditError, generate_key


def _log_with(n, key=None, path=None, marker="a"):
    """En logg med n poster. Samma nyckel gar att aterge for att bygga en
    konkurrerande kedja som ar internt giltig men inte var den vi ankrade."""
    key = key or generate_key()
    if path is None:
        path = os.path.join(tempfile.mkdtemp(prefix="axiomgate-kernel-anchor-"), "audit.log")
    log = AuditLog(path, key)
    for i in range(n):
        log.append({"marker": marker, "n": i})
    return log, path, key


def _cut_to(path, n):
    """Kapa loggen till n rader. Resultatet ar en internt konsistent kedja."""
    lines = open(path, encoding="utf-8").read().splitlines(True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("".join(lines[:n]))


# --- R2 (1): prefixverifiering ---------------------------------------------

def test_a_growing_log_verifies_against_an_older_anchor():
    """Kardan: ankaret ar gammalt, loggen har vaxt, och inget ar fel.

    Det ar hela poangen med prefixfragan. Den exakta kontrollen sager nej pa
    exakt samma logg -- inte for att nagot hant, utan for att tiden gatt.
    """
    log, _p, _k = _log_with(3)
    anchor = log.head()
    for i in range(2):
        log.append({"later": i})

    ok, msg, _last, count = log.verify_prefix(*anchor)
    assert ok, msg
    assert count == 5
    assert "3" in msg and "2" in msg, f"meddelandet ska saga hur mycket som tillkommit: {msg}"

    exact_ok, exact_msg, _ = log.verify_chain(*anchor)
    assert not exact_ok
    assert "longer than anchor" in exact_msg


def test_prefix_verification_still_catches_a_truncated_tail():
    """Prefixfragan far inte kosta det den exakta kontrollen redan kunde."""
    log, path, key = _log_with(5)
    anchor = log.head()
    _cut_to(path, 3)

    reopened = AuditLog(path, key)
    ok, msg, _last, count = reopened.verify_prefix(*anchor)
    assert not ok
    assert "truncat" in msg
    assert count == 3


def test_a_substituted_chain_breaks_the_prefix():
    """En annan kedja med samma nyckel ar internt giltig -- och inte var vi ankrade.

    Detta ar angreppet prefixverifieringen finns for: inte en kapad svans,
    utan en logg som bytts ut mot en egentillverkad med samma langd.
    """
    log, path, key = _log_with(3, marker="a")
    anchor = log.head()

    os.remove(path)
    forged, _p, _k = _log_with(3, key=key, path=path, marker="b")
    ok_internal, _msg, _ = forged.verify_chain()
    assert ok_internal, "den falska kedjan ar internt konsistent -- det ar forutsattningen"

    ok, msg, _last, _count = forged.verify_prefix(*anchor)
    assert not ok
    assert "anchor" in msg


def test_prefix_verification_needs_both_halves_of_the_anchor():
    """En hash utan position sager inte VAR den skulle sitta. Fail-closed."""
    log, _p, _k = _log_with(3)
    head, count = log.head()

    for args in ((head, None), (None, count), (None, None)):
        ok, msg, _last, _c = log.verify_prefix(*args)
        assert not ok, f"{args} borde avvisas"
        assert "both halves" in msg


def test_an_internally_broken_chain_fails_the_prefix_check_first():
    """Ett matchande prefix i en manipulerad logg ar inget godkannande."""
    log, path, key = _log_with(4)
    anchor = log.head()

    import json
    lines = open(path, encoding="utf-8").read().splitlines()
    entry = json.loads(lines[3])
    entry["marker"] = "z"          # hashen rakas INTE om -- det ar manipulation
    lines[3] = json.dumps(entry)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")

    # Konstruktorn skulle vagra oppna filen alls (bruten kedja, inte kapad
    # svans), sa kontrollen gors pa instansen som redan pekar pa den.
    ok, msg, _last, _count = log.verify_prefix(*anchor)
    assert not ok
    assert "mismatch" in msg


def test_an_anchor_of_zero_entries_is_honest_about_proving_nothing():
    """Ett ankare taget fore forsta posten kan inte upptacka nagon kapning."""
    log, _p, _k = _log_with(0)
    anchor = log.head()
    assert anchor == (None, 0)
    log.append({"n": 0})

    ok, msg, _last, _count = log.verify_prefix(*anchor)
    assert ok, msg
    assert "proves nothing" in msg or "anchors nothing" in msg


# --- R2 (2): ankaret gar att krava redan vid oppningen ---------------------

def test_an_anchored_constructor_refuses_a_truncated_log():
    """Det tillfalle en kapad svans annars aldrig upptacks."""
    log, path, key = _log_with(5)
    anchor = log.head()
    _cut_to(path, 3)

    with pytest.raises(AuditError) as exc:
        AuditLog(path, key, anchor=anchor)
    assert "truncat" in str(exc.value)


def test_an_anchored_constructor_opens_a_log_that_has_grown():
    """Ett ankare far inte bli en grind som stanger sa fort loggen anvands."""
    log, path, key = _log_with(3)
    anchor = log.head()
    log.append({"later": 0})

    reopened = AuditLog(path, key, anchor=anchor)
    assert reopened.head()[1] == 4


def test_an_anchored_constructor_refuses_a_substituted_chain():
    log, path, key = _log_with(3, marker="a")
    anchor = log.head()
    os.remove(path)
    _log_with(3, key=key, path=path, marker="b")

    with pytest.raises(AuditError) as exc:
        AuditLog(path, key, anchor=anchor)
    assert "anchor" in str(exc.value)


def test_the_unanchored_constructor_is_unchanged():
    """Den deklarerade luckan: utan ankare oppnar en kapad kedja tyst.

    Samma sorts grans som R1:s flagga. Den star i ROADMAP och far inte
    stangas av misstag -- men den far heller inte tystas bort harifran.
    """
    log, path, key = _log_with(5)
    _cut_to(path, 2)

    reopened = AuditLog(path, key)
    assert reopened.head()[1] == 2
    ok, _msg, _ = reopened.verify_chain()
    assert ok, "internt konsistent -- det ar precis varfor ankaret behovs"


def test_the_anchor_is_checked_after_the_tail_is_healed():
    """En krasch mitt i en skrivning lagas -- men lakningen far inte dolja
    att en ankrad post forsvann med den."""
    log, path, key = _log_with(4)
    anchor = log.head()

    with open(path, "a", encoding="utf-8") as handle:
        handle.write('{"incomplete": ')
    _cut_to(path, 3)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write('{"incomplete": ')

    with pytest.raises(AuditError) as exc:
        AuditLog(path, key, anchor=anchor)
    assert "truncat" in str(exc.value)


def test_an_incoherent_anchor_count_is_not_reported_as_tampering():
    """Granskningsfynd 2026-09-10: ett ogiltigt argument sa 'the log was replaced'.

    `anchor_count` negativt, eller noll med en satt `anchor_head`, ar inte ett
    ankare -- det ar ett anropsfel. Bada var tekniskt 'not None', slapp darfor
    forbi halvankarkontrollen, och foll ut som prefix mismatch. Kontrollen
    nekade ratt, men meddelandet pastod manipulation dar loggen var orord. En
    granskare som lasar det jagar en angripare som inte finns.
    """
    log, _path, _key = _log_with(4)
    head, _count = log.head()

    for bad_count in (-1, 0):
        ok, msg, _last, _n = log.verify_prefix(head, bad_count)
        assert ok is False
        assert "replaced" not in msg, f"anchor_count={bad_count}: {msg}"
        assert "anchor_count" in msg

    # Och det akta nollankaret -- ingen head, noll poster -- ska fortfarande ha
    # kvar sitt eget arliga svar. Det ar inte ett anropsfel.
    ok, msg, _last, _n = log.verify_prefix(None, 0)
    assert ok is True
    assert "none of them anchored" in msg
