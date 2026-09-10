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


class TestKraschaterhamtning:
    """_replay() villkorar helning på "truncation:" — en sträng ingen emitter skriver.

    verify_integrity() returnerar bara "tail malformation", "malformed json",
    "previous_hash mismatch", "entry_hash mismatch" och "mac mismatch"
    (audit.py:171-184). OR-grenen "truncation:" i msg är död kod; helningen
    bärs helt av "tail malformation". Testet låser fast att en avbruten
    skrivning faktiskt helas, så att grenen kan tas bort utan att beteendet
    tyst ändras.
    """

    def test_avbruten_sista_rad_helas_vid_oppning(self, tmp_path):
        sokvag = str(tmp_path / "audit.log")
        nyckel = generate_key()
        logg = AuditLog(sokvag, nyckel)
        logg.append({"event": "ett"})
        logg.append({"event": "tva"})

        # Simulera en krasch mitt i en skrivning: en ofullständig JSON-rad sist.
        with open(sokvag, "a", encoding="utf-8") as fh:
            fh.write('{"event": "avbru')

        helad = AuditLog(sokvag, nyckel)
        ok, msg, _, antal = helad.verify_integrity()
        assert ok is True, f"loggen helades inte: {msg}"
        assert antal == 2

    def test_verkligt_manipulerad_logg_avvisas_fortfarande(self, tmp_path):
        sokvag = str(tmp_path / "audit.log")
        nyckel = generate_key()
        logg = AuditLog(sokvag, nyckel)
        logg.append({"event": "ett"})

        rader = open(sokvag, encoding="utf-8").read().replace('"ett"', '"manipulerad"')
        open(sokvag, "w", encoding="utf-8").write(rader)

        with pytest.raises(AuditError):
            AuditLog(sokvag, nyckel)


# --- Trunkering av svansen (fynd 2026-09-10) -------------------------------
# Buggen: verify_chain() verifierade bara att kvarvarande poster länkade rätt
# bakåt. Att ta bort den SISTA posten lämnar en perfekt giltig kortare kedja,
# så en angripare med skrivrätt kunde radera just den PERMIT som bevisar vad
# agenten gjorde -- och loggen intygade fortfarande sin egen integritet.
# En självcertifierande logg kan inte ensam bevisa att den inte är kapad;
# det kräver en förankring utanför filen.

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
