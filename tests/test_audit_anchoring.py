"""R2: an anchor should be checkable against a log that is still growing.

verify_chain only answers "is this exactly the log I anchored?". That
question cannot be asked of a live log: the next entry makes the answer no,
and the message "log longer than anchor" is not a finding, just that time
has passed. So an anchored check could in practice only ever be run against
a frozen archive -- and was therefore run rarely or never.

This file tests the other question: does the log START with the chain I
anchored? And it tests that the answer can be demanded already when the log
is opened, which is the one moment a hijacked tail otherwise never gets
caught: AuditLog(path, key) replays a truncated chain without complaint,
because a truncated chain is internally consistent.
"""

import os
import tempfile

import pytest

from axiomgate_kernel import AuditLog, AuditError, generate_key


def _log_with(n, key=None, path=None, marker="a"):
    """A log with n entries. The same key can be reused to build a
    competing chain that is internally valid but not the one we anchored."""
    key = key or generate_key()
    if path is None:
        path = os.path.join(tempfile.mkdtemp(prefix="axiomgate-kernel-anchor-"), "audit.log")
    log = AuditLog(path, key)
    for i in range(n):
        log.append({"marker": marker, "n": i})
    return log, path, key


def _cut_to(path, n):
    """Cut the log down to n lines. The result is an internally consistent chain."""
    lines = open(path, encoding="utf-8").read().splitlines(True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("".join(lines[:n]))


# --- R2 (1): prefix verification --------------------------------------------

def test_a_growing_log_verifies_against_an_older_anchor():
    """The core case: the anchor is old, the log has grown, and nothing is wrong.

    That is the entire point of the prefix question. The exact check says no
    on this very same log -- not because anything happened, but because time
    has passed.
    """
    log, _p, _k = _log_with(3)
    anchor = log.head()
    for i in range(2):
        log.append({"later": i})

    ok, msg, _last, count = log.verify_prefix(*anchor)
    assert ok, msg
    assert count == 5
    assert "3" in msg and "2" in msg, f"message should say how much was added: {msg}"

    exact_ok, exact_msg, _ = log.verify_chain(*anchor)
    assert not exact_ok
    assert "longer than anchor" in exact_msg


def test_prefix_verification_still_catches_a_truncated_tail():
    """The prefix question must not cost what the exact check could already do."""
    log, path, key = _log_with(5)
    anchor = log.head()
    _cut_to(path, 3)

    reopened = AuditLog(path, key)
    ok, msg, _last, count = reopened.verify_prefix(*anchor)
    assert not ok
    assert "truncat" in msg
    assert count == 3


def test_a_substituted_chain_breaks_the_prefix():
    """Another chain with the same key is internally valid -- and not the
    one we anchored.

    This is the attack prefix verification exists for: not a hijacked tail,
    but a log swapped out for a self-made one of the same length.
    """
    log, path, key = _log_with(3, marker="a")
    anchor = log.head()

    os.remove(path)
    forged, _p, _k = _log_with(3, key=key, path=path, marker="b")
    ok_internal, _msg, _ = forged.verify_chain()
    assert ok_internal, "forged chain must be internally consistent -- the premise"

    ok, msg, _last, _count = forged.verify_prefix(*anchor)
    assert not ok
    assert "anchor" in msg


def test_prefix_verification_needs_both_halves_of_the_anchor():
    """A hash without a position does not say WHERE it should sit. Fail-closed."""
    log, _p, _k = _log_with(3)
    head, count = log.head()

    for args in ((head, None), (None, count), (None, None)):
        ok, msg, _last, _c = log.verify_prefix(*args)
        assert not ok, f"{args} should be rejected"
        assert "both halves" in msg


def test_an_internally_broken_chain_fails_the_prefix_check_first():
    """A matching prefix in a tampered log is not an approval."""
    log, path, key = _log_with(4)
    anchor = log.head()

    import json
    lines = open(path, encoding="utf-8").read().splitlines()
    entry = json.loads(lines[3])
    entry["marker"] = "z"          # the hash is NOT recomputed -- that is tampering
    lines[3] = json.dumps(entry)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")

    # The constructor would refuse to open the file at all (broken chain, not
    # a hijacked tail), so the check runs on the instance that already
    # points to it.
    ok, msg, _last, _count = log.verify_prefix(*anchor)
    assert not ok
    assert "mismatch" in msg


def test_an_anchor_of_zero_entries_is_honest_about_proving_nothing():
    """An anchor taken before the first entry cannot detect any hijacking."""
    log, _p, _k = _log_with(0)
    anchor = log.head()
    assert anchor == (None, 0)
    log.append({"n": 0})

    ok, msg, _last, _count = log.verify_prefix(*anchor)
    assert ok, msg
    assert "proves nothing" in msg or "anchors nothing" in msg


# --- R2 (2): the anchor can be demanded already at open time ---------------

def test_an_anchored_constructor_refuses_a_truncated_log():
    """The one moment a hijacked tail otherwise never gets caught."""
    log, path, key = _log_with(5)
    anchor = log.head()
    _cut_to(path, 3)

    with pytest.raises(AuditError) as exc:
        AuditLog(path, key, anchor=anchor)
    assert "truncat" in str(exc.value)


def test_an_anchored_constructor_opens_a_log_that_has_grown():
    """An anchor must not become a gate that shuts as soon as the log is used."""
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
    """The declared gap: without an anchor, a hijacked chain opens silently.

    The same kind of boundary as R1's flag. It is written in the ROADMAP and
    must not be closed by accident -- but it must not be silenced away from
    here either.
    """
    log, path, key = _log_with(5)
    _cut_to(path, 2)

    reopened = AuditLog(path, key)
    assert reopened.head()[1] == 2
    ok, _msg, _ = reopened.verify_chain()
    assert ok, "internally consistent -- that is exactly why the anchor is needed"


def test_the_anchor_is_checked_after_the_tail_is_healed():
    """A crash mid-write is healed -- but the healing must not hide
    that an anchored entry disappeared along with it."""
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
    """Audit finding 2026-09-10: an invalid argument said 'the log was replaced'.

    A negative `anchor_count`, or zero with a set `anchor_head`, is not an
    anchor -- it is a call error. Both were technically 'not None', so they
    slipped past the half-anchor check and fell through as a prefix mismatch.
    The check correctly denied, but the message claimed tampering where the
    log was untouched. A reviewer reading it would chase an attacker that
    does not exist.
    """
    log, _path, _key = _log_with(4)
    head, _count = log.head()

    for bad_count in (-1, 0):
        ok, msg, _last, _n = log.verify_prefix(head, bad_count)
        assert ok is False
        assert "replaced" not in msg, f"anchor_count={bad_count}: {msg}"
        assert "anchor_count" in msg

    # And the genuine zero-anchor -- no head, zero entries -- should still
    # keep its own honest answer. That is not a call error.
    ok, msg, _last, _n = log.verify_prefix(None, 0)
    assert ok is True
    assert "none of them anchored" in msg
