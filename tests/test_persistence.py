"""AxiomGate Kernel — Persistence Property Tests

Tests for SQLite persistence layer with explicit serialization.
"""

import os
import tempfile
import shutil
import pytest
from datetime import datetime, timedelta, timezone

from axiomgate_kernel import (
    ActionType, RiskLevel, Role, make_capability,
)
from axiomgate_kernel.serializers import (
    capability_to_persist, capability_from_persist,
    evidence_to_persist, evidence_from_persist,
    escalation_to_persist, escalation_from_persist,
)
from axiomgate_kernel.persistence import (
    CapabilityStore, EvidenceStore, EscalationStore, GovernanceStateStore,
)


@pytest.fixture
def tmp_db_dir():
    """Create a temporary directory for test databases."""
    tmpdir = tempfile.mkdtemp()
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


def _make_cap(**overrides):
    """Helper to create a capability with defaults."""
    defaults = dict(
        capability_id="cap-1",
        principal_id="agent-a",
        role=Role.R_ENG,
        domains=["code", "research"],
        action_types=[ActionType.INSPECT, ActionType.EXECUTE],
        risk_ceiling=RiskLevel.MEDIUM,
        issued_by="Owner",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    defaults.update(overrides)
    return make_capability(**defaults)


# --- Serialization Round-Trip Tests ---

class TestCapabilitySerialization:
    """Test capability serialization determinism and round-trip."""

    def test_round_trip_preserves_all_fields(self):
        """Same logical capability → same serialized representation."""
        cap = _make_cap()
        persist = capability_to_persist(cap)
        restored = capability_from_persist(persist)
        assert restored.capability_id == cap.capability_id
        assert restored.principal_id == cap.principal_id
        assert restored.role == cap.role
        assert restored.domains == cap.domains
        assert restored.action_types == cap.action_types
        assert restored.risk_ceiling == cap.risk_ceiling
        assert restored.issued_by == cap.issued_by
        assert restored.transferable == cap.transferable
        assert restored.delegation_depth == cap.delegation_depth

    def test_deterministic_representation(self):
        """Same capability → same persistence dict (deterministic)."""
        cap = _make_cap()
        p1 = capability_to_persist(cap)
        p2 = capability_to_persist(cap)
        assert p1 == p2

    def test_frozenset_ordering_invariant(self):
        """Frozenset ordering does not change representation."""
        cap1 = _make_cap(domains=["z", "a", "m"])
        cap2 = _make_cap(domains=["a", "m", "z"])
        p1 = capability_to_persist(cap1)
        p2 = capability_to_persist(cap2)
        assert p1["domains"] == sorted(["a", "m", "z"])

    def test_enum_representation_deterministic(self):
        """Enum representation is deterministic."""
        cap = _make_cap(role=Role.R_ENG, risk_ceiling=RiskLevel.HIGH)
        persist = capability_to_persist(cap)
        assert persist["role"] == "R-ENG"
        assert persist["risk_ceiling"] == "HIGH"

    def test_datetime_representation_deterministic(self):
        """Datetime representation is deterministic."""
        dt = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        cap = _make_cap(issued_at=dt, expires_at=dt + timedelta(hours=1))
        persist = capability_to_persist(cap)
        assert persist["issued_at"] == "2026-01-15T12:00:00+00:00"

    def test_integrity_hash_stable(self):
        """Integrity hash remains stable across equivalent construction."""
        from datetime import datetime, timezone
        fixed_dt = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        cap1 = _make_cap(issued_at=fixed_dt, expires_at=fixed_dt + timedelta(hours=1))
        cap2 = _make_cap(issued_at=fixed_dt, expires_at=fixed_dt + timedelta(hours=1))
        p1 = capability_to_persist(cap1)
        p2 = capability_to_persist(cap2)
        import json
        from axiomgate_kernel.crypto import sha256_hex
        h1 = sha256_hex(json.dumps(p1, sort_keys=True).encode())
        h2 = sha256_hex(json.dumps(p2, sort_keys=True).encode())
        assert h1 == h2

    def test_different_capability_different_representation(self):
        """Different capability → different representation where security fields differ."""
        cap1 = _make_cap(capability_id="cap-1")
        cap2 = _make_cap(capability_id="cap-2")
        p1 = capability_to_persist(cap1)
        p2 = capability_to_persist(cap2)
        assert p1 != p2

    def test_malformed_persisted_data_fails_closed(self):
        """Malformed persisted representation raises error."""
        with pytest.raises((ValueError, KeyError)):
            capability_from_persist({"capability_id": "cap-1"})  # Missing required fields

    def test_invalid_enum_value_fails_closed(self):
        """Invalid enum value in persisted data raises error."""
        with pytest.raises(ValueError):
            capability_from_persist({
                "capability_id": "cap-1",
                "principal_id": "agent-a",
                "role": "INVALID_ROLE",  # Not a valid Role value
                "domains": ["code"],
                "action_types": ["EXECUTE"],
                "risk_ceiling": "MEDIUM",
                "issued_by": "Owner",
                "issued_at": "2026-01-01T00:00:00+00:00",
                "expires_at": "2026-01-01T01:00:00+00:00",
                "transferable": False,
                "delegation_depth": 1,
            })


class TestEvidenceSerialization:
    """Test evidence serialization round-trip."""

    def test_round_trip(self):
        """Evidence record round-trips correctly."""
        from axiomgate_kernel import EvidenceJournal, Principal
        j = EvidenceJournal()
        j.create_candidate("ev-1", "agent-a", {"data": "test"})
        record = j.get("ev-1")
        persist = evidence_to_persist(record)
        restored = evidence_from_persist(persist)
        assert restored.evidence_id == record.evidence_id
        assert restored.producer_id == record.producer_id
        assert restored.state == record.state


class TestEscalationSerialization:
    """Test escalation serialization round-trip."""

    def test_round_trip(self):
        """Escalation record round-trips correctly."""
        from axiomgate_kernel import EscalationStore, EscalationStatus
        store = EscalationStore()
        record = store.create("esc-1", "req-1", "agent-a", "hash", "reason", "other")
        persist = escalation_to_persist(record)
        restored = escalation_from_persist(persist)
        assert restored.escalation_id == record.escalation_id
        assert restored.status == record.status


# --- Persistence Store Tests ---

class TestCapabilityStore:
    """Test persistent capability storage."""

    def test_store_and_load(self, tmp_db_dir):
        """Capability can be stored and loaded."""
        store = CapabilityStore(os.path.join(tmp_db_dir, "caps.db"))
        cap = _make_cap()
        store.store(cap)
        loaded = store.load("cap-1")
        assert loaded is not None
        assert loaded.capability_id == "cap-1"
        assert loaded.principal_id == "agent-a"
        assert loaded.role == Role.R_ENG
        store.close()

    def test_load_nonexistent_returns_none(self, tmp_db_dir):
        """Loading nonexistent capability returns None."""
        store = CapabilityStore(os.path.join(tmp_db_dir, "caps.db"))
        assert store.load("nonexistent") is None
        store.close()

    def test_load_all(self, tmp_db_dir):
        """load_all returns all capabilities."""
        store = CapabilityStore(os.path.join(tmp_db_dir, "caps.db"))
        for i in range(3):
            store.store(_make_cap(capability_id=f"cap-{i}"))
        all_caps = store.load_all()
        assert len(all_caps) == 3
        store.close()

    def test_revoke(self, tmp_db_dir):
        """Revoked capability has revoked_at set."""
        store = CapabilityStore(os.path.join(tmp_db_dir, "caps.db"))
        store.store(_make_cap())
        store.revoke("cap-1", datetime.now(timezone.utc).isoformat())
        loaded = store.load("cap-1")
        assert loaded.revoked_at is not None
        store.close()

    def test_integrity_verification(self, tmp_db_dir):
        """Integrity check passes for unmodified data."""
        store = CapabilityStore(os.path.join(tmp_db_dir, "caps.db"))
        store.store(_make_cap())
        assert store.verify_integrity() is True
        store.close()


class TestEvidenceStore:
    """Test persistent evidence storage."""

    def test_store_and_load_record(self, tmp_db_dir):
        """Evidence record can be stored and loaded."""
        store = EvidenceStore(os.path.join(tmp_db_dir, "evidence.db"))
        from axiomgate_kernel import EvidenceJournal
        j = EvidenceJournal()
        j.create_candidate("ev-1", "agent-a", {"data": "test"})
        record = j.get("ev-1")
        store.store_record(record)
        loaded = store.load_record("ev-1")
        assert loaded is not None
        assert loaded.evidence_id == "ev-1"
        store.close()

    def test_append_event(self, tmp_db_dir):
        """Events are appended."""
        store = EvidenceStore(os.path.join(tmp_db_dir, "evidence.db"))
        store.append_event({
            "evidence_id": "ev-1",
            "event": "create_candidate",
            "state": "CANDIDATE",
            "actor": "agent-a",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "detail": {},
        })
        events = store.load_events("ev-1")
        assert len(events) == 1
        assert events[0]["event"] == "create_candidate"
        store.close()


class TestGovernanceStateStore:
    """Test persistent governance state storage."""

    def test_set_and_get(self, tmp_db_dir):
        """State can be set and retrieved."""
        store = GovernanceStateStore(os.path.join(tmp_db_dir, "state.db"))
        store.set("version", "1.0")
        assert store.get("version") == "1.0"
        store.close()

    def test_integrity_verification(self, tmp_db_dir):
        """Integrity check passes for unmodified state."""
        store = GovernanceStateStore(os.path.join(tmp_db_dir, "state.db"))
        store.set("key1", "value1")
        assert store.verify_integrity() is True
        store.close()

    def test_integrity_tamper_detected(self, tmp_db_dir):
        """Integrity check detects tampering."""
        store = GovernanceStateStore(os.path.join(tmp_db_dir, "state.db"))
        store.set("key1", "value1")
        store.execute("UPDATE governance_state SET value = '\"tampered\"' WHERE key = 'key1'")
        store.commit()
        assert store.verify_integrity() is False
        store.close()


class TestPersistenceProperties:
    """Test persistence architectural properties."""

    def test_wal_mode_enabled(self, tmp_db_dir):
        """WAL mode is enabled for crash recovery."""
        store = CapabilityStore(os.path.join(tmp_db_dir, "caps.db"))
        result = store.execute("PRAGMA journal_mode").fetchone()
        assert result[0] == "wal"
        store.close()

    def test_concurrent_readers(self, tmp_db_dir):
        """Multiple readers can access the database simultaneously via separate connections."""
        import threading
        db_path = os.path.join(tmp_db_dir, "caps.db")
        store = CapabilityStore(db_path)
        store.store(_make_cap())
        store.close()

        results = []
        def reader():
            for _ in range(10):
                s = CapabilityStore(db_path)
                loaded = s.load("cap-1")
                results.append(loaded is not None)
                s.close()

        threads = [threading.Thread(target=reader) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(results)


class TestSQLiteConcurrency:
    """Test SQLite concurrency semantics with shared connection."""

    def test_concurrent_writes_serialized(self, tmp_db_dir):
        """Concurrent writes to same store are serialized by _lock."""
        import threading

        db_path = os.path.join(tmp_db_dir, "concurrent.db")
        store = CapabilityStore(db_path)

        results = []
        errors = []

        def writer(thread_id):
            try:
                for i in range(5):
                    cap = _make_cap(
                        capability_id=f"cap-t{thread_id}-{i}",
                        principal_id=f"agent-{thread_id}",
                    )
                    store.store(cap)
                    results.append(f"t{thread_id}-ok-{i}")
            except Exception as e:
                errors.append(f"t{thread_id}-error-{e}")

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(errors) == 0, f"Concurrent write errors: {errors}"
        assert len(results) == 25
        all_caps = store.load_all()
        assert len(all_caps) == 25
        store.close()

    def test_concurrent_read_write(self, tmp_db_dir):
        """Concurrent reads and writes to same store are safe."""
        import threading

        db_path = os.path.join(tmp_db_dir, "rw.db")
        store = CapabilityStore(db_path)

        for i in range(10):
            store.store(_make_cap(capability_id=f"cap-{i}"))

        read_results = []
        write_results = []
        errors = []

        def reader():
            try:
                for _ in range(20):
                    cap = store.load("cap-0")
                    read_results.append(cap is not None)
            except Exception as e:
                errors.append(f"read-error-{e}")

        def writer():
            try:
                for i in range(10):
                    store.store(_make_cap(capability_id=f"cap-new-{i}"))
                    write_results.append(True)
            except Exception as e:
                errors.append(f"write-error-{e}")

        threads = [
            threading.Thread(target=reader),
            threading.Thread(target=reader),
            threading.Thread(target=writer),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(errors) == 0, f"Concurrent read/write errors: {errors}"
        assert all(read_results)
        assert len(write_results) == 10
        store.close()

    def test_transaction_rollback(self, tmp_db_dir):
        """Transaction rollback works correctly."""
        db_path = os.path.join(tmp_db_dir, "rollback.db")
        store = CapabilityStore(db_path)

        store.store(_make_cap(capability_id="cap-original"))

        try:
            store.execute("INSERT INTO capabilities (capability_id) VALUES ('cap-bad')")
            store.rollback()
        except Exception:
            store.rollback()

        loaded = store.load("cap-original")
        assert loaded is not None
        bad = store.load("cap-bad")
        assert bad is None
        store.close()

    def test_store_close_prevents_further_ops(self, tmp_db_dir):
        """Closed store raises PersistenceError on operations."""
        from axiomgate_kernel.persistence import PersistenceError
        db_path = os.path.join(tmp_db_dir, "close.db")
        store = CapabilityStore(db_path)
        store.store(_make_cap())
        store.close()

        with pytest.raises(PersistenceError):
            store.load("cap-1")

        with pytest.raises(PersistenceError):
            store.execute("SELECT 1")

        # commit() is a no-op after close (by design)
        store.commit()


class TestRevokePreservesIntegrityHash:
    """revoke() writes revoked_at but never recomputes integrity_hash.

    revoked_at is part of persist_data, which is hashed on store
    (persistence.py:136), so an UPDATE of the column makes the stored hash
    wrong. verify_integrity() returns False on the first mismatching row --
    a single revoked capability therefore makes the entire capability store
    report tampering.
    """

    def test_verify_integrity_holds_after_revoke(self, tmp_path):
        now = datetime.now(timezone.utc)
        store = CapabilityStore(str(tmp_path / "caps.db"))
        cap = make_capability(
            capability_id="cap-revoke", principal_id="agent:t", role=Role.R_ENG,
            domains=frozenset({"tool:*"}),
            action_types=frozenset([ActionType.EXECUTE]),
            risk_ceiling=RiskLevel.HIGH, issued_by="Owner",
            issued_at=now, expires_at=now + timedelta(days=1),
        )
        store.store(cap)
        assert store.verify_integrity() is True

        store.revoke("cap-revoke", now.isoformat())
        assert store.verify_integrity() is True, (
            "revoke() updated revoked_at without recomputing integrity_hash"
        )

    def test_revoke_is_visible_in_loaded_capability(self, tmp_path):
        now = datetime.now(timezone.utc)
        store = CapabilityStore(str(tmp_path / "caps.db"))
        cap = make_capability(
            capability_id="cap-syns", principal_id="agent:t", role=Role.R_ENG,
            domains=frozenset({"tool:*"}),
            action_types=frozenset([ActionType.EXECUTE]),
            risk_ceiling=RiskLevel.HIGH, issued_by="Owner",
            issued_at=now, expires_at=now + timedelta(days=1),
        )
        store.store(cap)
        store.revoke("cap-syns", now.isoformat())
        assert store.load("cap-syns").revoked_at is not None
