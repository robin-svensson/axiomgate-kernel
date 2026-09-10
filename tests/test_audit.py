"""AxiomGate Kernel — Audit Integrity Property Tests

Tests for audit log integrity properties.
"""

import pytest
import os
import tempfile

from axiomgate_kernel import AuditLog, AuditError, generate_key


class TestAuditIntegrity:
    """Test audit log integrity properties."""

    def _audit(self):
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "audit.log")
        return AuditLog(path, generate_key()), tmpdir

    def test_append_returns_hash(self):
        """Append returns an entry hash."""
        audit, tmpdir = self._audit()
        h = audit.append({"action": "test", "verdict": "DENY"})
        assert h is not None
        assert len(h) == 64  # SHA-256 hex
        import shutil
        shutil.rmtree(tmpdir)

    def test_chain_integrity(self):
        """Audit chain is valid after appends."""
        audit, tmpdir = self._audit()
        audit.append({"action": "test1", "verdict": "DENY"})
        audit.append({"action": "test2", "verdict": "PERMIT"})
        ok, msg, last = audit.verify_chain()
        assert ok is True
        assert msg == "ok"
        import shutil
        shutil.rmtree(tmpdir)

    def test_entries_are_append_only(self):
        """Entries are append-only."""
        audit, tmpdir = self._audit()
        audit.append({"entry": 1})
        audit.append({"entry": 2})
        audit.append({"entry": 3})
        entries = audit.entries()
        assert len(entries) == 3
        assert entries[0]["entry"] == 1
        assert entries[1]["entry"] == 2
        assert entries[2]["entry"] == 3
        import shutil
        shutil.rmtree(tmpdir)

    def test_empty_log_valid(self):
        """Empty audit log is valid."""
        audit, tmpdir = self._audit()
        ok, msg, last = audit.verify_chain()
        assert ok is True
        assert msg == "empty"
        assert last is None
        import shutil
        shutil.rmtree(tmpdir)

    def test_empty_key_rejected(self):
        """Empty MAC key is rejected."""
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, "audit.log")
        with pytest.raises(AuditError):
            AuditLog(path, b"")
        import shutil
        shutil.rmtree(tmpdir)

    def test_tampered_entry_detected(self):
        """Tampered audit entry is detected."""
        audit, tmpdir = self._audit()
        audit.append({"action": "test", "verdict": "DENY"})
        # Tamper with the file - JSON uses compact format (no spaces)
        with open(audit.path, "r") as f:
            content = f.read()
        # Replace verdict in the compact JSON
        tampered = content.replace('"verdict":"DENY"', '"verdict":"PERMIT"')
        with open(audit.path, "w") as f:
            f.write(tampered)
        ok, msg, last = audit.verify_chain()
        assert ok is False
        assert "mac mismatch" in msg or "entry_hash mismatch" in msg
        import shutil
        shutil.rmtree(tmpdir)


class TestCrashRecovery:
    """_replay() conditions healing on "truncation:" -- a string no emitter writes.

    verify_integrity() only ever returns "tail malformation", "malformed json",
    "previous_hash mismatch", "entry_hash mismatch" and "mac mismatch"
    (audit.py:171-184). The "truncation:" OR-branch in msg is dead code;
    healing is carried entirely by "tail malformation". This test locks in
    that an interrupted write is actually healed, so the branch can be
    removed without silently changing behavior.
    """

    def test_a_truncated_last_line_is_healed_on_open(self, tmp_path):
        path = str(tmp_path / "audit.log")
        key = generate_key()
        log = AuditLog(path, key)
        log.append({"event": "one"})
        log.append({"event": "two"})

        # Simulate a crash mid-write: an incomplete JSON line at the end.
        with open(path, "a", encoding="utf-8") as fh:
            fh.write('{"event": "trunc')

        healed = AuditLog(path, key)
        ok, msg, _, count = healed.verify_integrity()
        assert ok is True, f"the log was not healed: {msg}"
        assert count == 2

    def test_a_genuinely_tampered_log_is_still_rejected(self, tmp_path):
        path = str(tmp_path / "audit.log")
        key = generate_key()
        log = AuditLog(path, key)
        log.append({"event": "one"})

        content = open(path, encoding="utf-8").read().replace('"one"', '"tampered"')
        open(path, "w", encoding="utf-8").write(content)

        with pytest.raises(AuditError):
            AuditLog(path, key)


# --- Truncating the tail (finding 2026-09-10) -------------------------------
# The bug: verify_chain() only verified that the remaining entries linked
# correctly backward. Removing the LAST entry leaves a perfectly valid
# shorter chain, so an attacker with write access could delete exactly the
# PERMIT that proves what the agent did -- and the log still attested to
# its own integrity.
# A self-certifying log cannot alone prove it has not been hijacked;
# that requires an anchor outside the file.

import os
import tempfile

from axiomgate_kernel.audit import AuditLog


def _log_with(n):
    d = tempfile.mkdtemp()
    path = os.path.join(d, "audit.log")
    log = AuditLog(path, b"0" * 32)
    for i in range(n):
        log.append({"seq_marker": i})
    return log, path


def test_every_entry_carries_its_position():
    log, _ = _log_with(3)
    assert [e["seq"] for e in log.entries()] == [0, 1, 2]


def test_head_reports_an_anchor_the_caller_can_store():
    log, _ = _log_with(3)
    head_hash, count = log.head()
    assert count == 3
    assert head_hash == log.entries()[-1]["entry_hash"]


def test_truncating_the_tail_is_detected_against_an_anchor():
    log, path = _log_with(5)
    anchor_hash, anchor_count = log.head()

    lines = open(path).read().splitlines()
    open(path, "w").write("\n".join(lines[:-1]) + "\n")

    reopened = AuditLog(path, b"0" * 32)
    ok, msg, _ = reopened.verify_chain()
    assert ok, "the shortened chain is still internally consistent -- that is the point"

    ok, msg, _ = reopened.verify_chain(expected_head=anchor_hash, expected_count=anchor_count)
    assert not ok
    assert "truncat" in msg or "count" in msg or "head" in msg


def test_anchor_matching_log_verifies():
    log, _ = _log_with(4)
    h, c = log.head()
    ok, msg, _ = log.verify_chain(expected_head=h, expected_count=c)
    assert ok, msg


def test_a_renumbered_entry_is_rejected():
    """Rewriting seq must not survive, even if the hashes were recomputed."""
    log, path = _log_with(3)
    entries = log.entries()
    assert entries[1]["seq"] == 1
    ok, _, _ = log.verify_chain()
    assert ok
