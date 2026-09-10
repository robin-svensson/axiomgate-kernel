"""AxiomGate Kernel — Persistence Layer

SQLite-backed persistence with WAL mode for atomicity and crash recovery.
Provides storage abstraction so authorization kernel is not coupled to SQLite.
"""

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .crypto import sha256_hex
from .serializers import (
    capability_to_persist, capability_from_persist,
    evidence_to_persist, evidence_from_persist,
    escalation_to_persist, escalation_from_persist,
    audit_record_to_persist,
)


class PersistenceError(Exception):
    """Raised when persistence operations fail."""
    pass


class Store:
    """Abstract base for persistent stores."""
    pass


class SQLiteStore(Store):
    """SQLite-backed persistent store with WAL mode.

    Properties:
    - Atomic transactions via SQLite WAL
    - Crash recovery via WAL replay
    - Concurrent readers with writer serialization
    - Durable state across restarts
    - Integrity hashes for corruption detection
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._connect()

    def _connect(self) -> None:
        """Establish connection with WAL mode."""
        directory = os.path.dirname(self._db_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._conn = sqlite3.connect(self._db_path, timeout=30, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.row_factory = sqlite3.Row

    def close(self) -> None:
        """Close the connection. Thread-safe via _lock."""
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute a SQL statement.

        NOTE: Callers requiring transactional integrity must hold _lock
        for the entire execute()+commit() sequence.
        """
        if self._conn is None:
            raise PersistenceError("Store is closed")
        return self._conn.execute(sql, params)

    def commit(self) -> None:
        """Commit the current transaction.

        NOTE: Callers requiring transactional integrity must hold _lock
        for the entire execute()+commit() sequence.
        """
        if self._conn:
            self._conn.commit()

    def rollback(self) -> None:
        """Rollback the current transaction.

        NOTE: Callers requiring transactional integrity must hold _lock
        for the entire execute()+rollback() sequence.
        """
        if self._conn:
            self._conn.rollback()


class CapabilityStore(SQLiteStore):
    """Persistent capability storage.

    Uses explicit serializer for deterministic round-trips.
    Integrity hash is computed from the canonical persistence representation.
    """

    def __init__(self, db_path: str) -> None:
        super().__init__(db_path)
        self._init_schema()

    def _init_schema(self) -> None:
        """Create the capabilities table."""
        self.execute("""
            CREATE TABLE IF NOT EXISTS capabilities (
                capability_id TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL,
                role TEXT NOT NULL,
                domains TEXT NOT NULL,
                action_types TEXT NOT NULL,
                risk_ceiling TEXT NOT NULL,
                issued_by TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                transferable INTEGER NOT NULL DEFAULT 0,
                delegation_depth INTEGER NOT NULL DEFAULT 1,
                revoked_at TEXT,
                integrity_hash TEXT NOT NULL
            )
        """)
        self.commit()

    def store(self, cap) -> None:
        """Store a Capability object.

        Uses explicit serializer for deterministic representation.
        Thread-safe: entire execute+commit under _lock.
        """
        persist_data = capability_to_persist(cap)
        integrity_hash = sha256_hex(json.dumps(persist_data, sort_keys=True).encode())
        with self._lock:
            self.execute("""
                INSERT OR REPLACE INTO capabilities
                (capability_id, principal_id, role, domains, action_types,
                 risk_ceiling, issued_by, issued_at, expires_at, transferable,
                 delegation_depth, revoked_at, integrity_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                persist_data["capability_id"],
                persist_data["principal_id"],
                persist_data["role"],
                json.dumps(persist_data["domains"]),
                json.dumps(persist_data["action_types"]),
                persist_data["risk_ceiling"],
                persist_data["issued_by"],
                persist_data["issued_at"],
                persist_data["expires_at"],
                1 if persist_data["transferable"] else 0,
                persist_data["delegation_depth"],
                persist_data.get("revoked_at"),
                integrity_hash,
            ))
            self.commit()

    def load(self, capability_id: str):
        """Load a Capability by ID. Thread-safe: full operation under _lock."""
        with self._lock:
            result = self.execute(
                "SELECT * FROM capabilities WHERE capability_id = ?",
                (capability_id,)
            )
            row = result.fetchone()
            if row is None:
                return None
            return self._row_to_capability(row)

    def load_all(self):
        """Load all capabilities. Thread-safe: full operation under _lock."""
        with self._lock:
            result = self.execute("SELECT * FROM capabilities")
            return [self._row_to_capability(row) for row in result.fetchall()]

    @staticmethod
    def _row_to_persist(row) -> dict:
        """Radens hashade form. En sanningskälla för både revoke och verify."""
        return {
            "capability_id": row["capability_id"],
            "principal_id": row["principal_id"],
            "role": row["role"],
            "domains": json.loads(row["domains"]),
            "action_types": json.loads(row["action_types"]),
            "risk_ceiling": row["risk_ceiling"],
            "issued_by": row["issued_by"],
            "issued_at": row["issued_at"],
            "expires_at": row["expires_at"],
            "transferable": bool(row["transferable"]),
            "delegation_depth": row["delegation_depth"],
            "revoked_at": row["revoked_at"],
        }

    def revoke(self, capability_id: str, revoked_at: str) -> None:
        """Revoke a capability. Thread-safe: entire execute+commit under _lock.

        revoked_at ingår i den hashade persist_data, så integrity_hash måste
        räknas om i samma transaktion. Gjordes det inte skulle verify_integrity()
        rapportera manipulation för hela lagret efter en enda återkallelse.
        """
        with self._lock:
            row = self.execute(
                "SELECT * FROM capabilities WHERE capability_id = ?",
                (capability_id,)
            ).fetchone()
            if row is None:
                return
            persist_data = self._row_to_persist(row)
            persist_data["revoked_at"] = revoked_at
            integrity_hash = sha256_hex(
                json.dumps(persist_data, sort_keys=True).encode()
            )
            self.execute(
                "UPDATE capabilities SET revoked_at = ?, integrity_hash = ? "
                "WHERE capability_id = ?",
                (revoked_at, integrity_hash, capability_id)
            )
            self.commit()

    def verify_integrity(self) -> bool:
        """Verify integrity of all stored capabilities. Thread-safe: under _lock."""
        with self._lock:
            result = self.execute("SELECT * FROM capabilities")
            rows = result.fetchall()
        for row in rows:
            persist_data = self._row_to_persist(row)
            expected_hash = sha256_hex(json.dumps(persist_data, sort_keys=True).encode())
            if row["integrity_hash"] != expected_hash:
                return False
        return True

    def _row_to_capability(self, row):
        """Reconstruct a Capability from a database row."""
        persist_data = {
            "capability_id": row["capability_id"],
            "principal_id": row["principal_id"],
            "role": row["role"],
            "domains": json.loads(row["domains"]),
            "action_types": json.loads(row["action_types"]),
            "risk_ceiling": row["risk_ceiling"],
            "issued_by": row["issued_by"],
            "issued_at": row["issued_at"],
            "expires_at": row["expires_at"],
            "transferable": bool(row["transferable"]),
            "delegation_depth": row["delegation_depth"],
            "revoked_at": row["revoked_at"],
        }
        return capability_from_persist(persist_data)


class EvidenceStore(SQLiteStore):
    """Persistent evidence storage."""

    def __init__(self, db_path: str) -> None:
        super().__init__(db_path)
        self._init_schema()

    def _init_schema(self) -> None:
        """Create the evidence tables."""
        self.execute("""
            CREATE TABLE IF NOT EXISTS evidence_records (
                evidence_id TEXT PRIMARY KEY,
                producer_id TEXT NOT NULL,
                state TEXT NOT NULL,
                content TEXT NOT NULL,
                verification_result INTEGER,
                verifier_id TEXT,
                authorization_result INTEGER,
                authorizer_id TEXT,
                integrity_hash TEXT NOT NULL
            )
        """)
        self.execute("""
            CREATE TABLE IF NOT EXISTS evidence_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id TEXT NOT NULL,
                event TEXT NOT NULL,
                state TEXT NOT NULL,
                actor TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                detail TEXT NOT NULL
            )
        """)
        self.commit()

    def store_record(self, record) -> None:
        """Store an EvidenceRecord. Thread-safe: entire execute+commit under _lock."""
        persist_data = evidence_to_persist(record)
        integrity_hash = sha256_hex(json.dumps(persist_data, sort_keys=True).encode())
        with self._lock:
            self.execute("""
                INSERT OR REPLACE INTO evidence_records
                (evidence_id, producer_id, state, content, verification_result,
                 verifier_id, authorization_result, authorizer_id, integrity_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                persist_data["evidence_id"],
                persist_data["producer_id"],
                persist_data["state"],
                json.dumps(persist_data["content"]),
                1 if persist_data.get("verification_result") else (0 if persist_data.get("verification_result") is False else None),
                persist_data.get("verifier_id"),
                1 if persist_data.get("authorization_result") else (0 if persist_data.get("authorization_result") is False else None),
                persist_data.get("authorizer_id"),
                integrity_hash,
            ))
            self.commit()

    def load_record(self, evidence_id: str):
        """Load an EvidenceRecord by ID. Thread-safe: under _lock."""
        with self._lock:
            result = self.execute(
                "SELECT * FROM evidence_records WHERE evidence_id = ?",
                (evidence_id,)
            )
            row = result.fetchone()
        if row is None:
            return None
        persist_data = {
            "evidence_id": row["evidence_id"],
            "producer_id": row["producer_id"],
            "state": row["state"],
            "content": json.loads(row["content"]),
            "verification_result": bool(row["verification_result"]) if row["verification_result"] is not None else None,
            "verifier_id": row["verifier_id"],
            "authorization_result": bool(row["authorization_result"]) if row["authorization_result"] is not None else None,
            "authorizer_id": row["authorizer_id"],
        }
        return evidence_from_persist(persist_data)

    def append_event(self, event_dict: Dict[str, Any]) -> None:
        """Append an evidence event (append-only). Thread-safe: under _lock."""
        with self._lock:
            self.execute("""
                INSERT INTO evidence_events
                (evidence_id, event, state, actor, timestamp, detail)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                event_dict["evidence_id"],
                event_dict["event"],
                event_dict["state"],
                event_dict["actor"],
                event_dict["timestamp"],
                json.dumps(event_dict.get("detail", {})),
            ))
            self.commit()

    def load_events(self, evidence_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Load evidence events. Thread-safe: under _lock."""
        with self._lock:
            if evidence_id:
                result = self.execute(
                    "SELECT * FROM evidence_events WHERE evidence_id = ? ORDER BY id",
                    (evidence_id,)
                )
            else:
                result = self.execute("SELECT * FROM evidence_events ORDER BY id")
            rows = result.fetchall()
        return [
            {
                "evidence_id": row["evidence_id"],
                "event": row["event"],
                "state": row["state"],
                "actor": row["actor"],
                "timestamp": row["timestamp"],
                "detail": json.loads(row["detail"]),
            }
            for row in rows
        ]


class EscalationStore(SQLiteStore):
    """Persistent escalation storage."""

    def __init__(self, db_path: str) -> None:
        super().__init__(db_path)
        self._init_schema()

    def _init_schema(self) -> None:
        """Create the escalations table."""
        self.execute("""
            CREATE TABLE IF NOT EXISTS escalations (
                escalation_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                payload_hash TEXT NOT NULL,
                reason TEXT NOT NULL,
                reason_class TEXT NOT NULL,
                status TEXT NOT NULL,
                owner_decision TEXT,
                owner_principal TEXT,
                created_at TEXT NOT NULL,
                decided_at TEXT,
                resolved_at TEXT
            )
        """)
        self.commit()

    def store(self, record) -> None:
        """Store an EscalationRecord. Thread-safe: under _lock."""
        persist_data = escalation_to_persist(record)
        with self._lock:
            self.execute("""
                INSERT OR REPLACE INTO escalations
                (escalation_id, request_id, principal_id, payload_hash, reason,
                 reason_class, status, owner_decision, owner_principal,
                 created_at, decided_at, resolved_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                persist_data["escalation_id"],
                persist_data["request_id"],
                persist_data["principal_id"],
                persist_data["payload_hash"],
                persist_data["reason"],
                persist_data["reason_class"],
                persist_data["status"],
                persist_data.get("owner_decision"),
                persist_data.get("owner_principal"),
                persist_data["created_at"],
                persist_data.get("decided_at"),
                persist_data.get("resolved_at"),
            ))
            self.commit()

    def load(self, escalation_id: str):
        """Load an EscalationRecord by ID. Thread-safe: under _lock."""
        with self._lock:
            result = self.execute(
                "SELECT * FROM escalations WHERE escalation_id = ?",
                (escalation_id,)
            )
            row = result.fetchone()
        if row is None:
            return None
        persist_data = {
            "escalation_id": row["escalation_id"],
            "request_id": row["request_id"],
            "principal_id": row["principal_id"],
            "payload_hash": row["payload_hash"],
            "reason": row["reason"],
            "reason_class": row["reason_class"],
            "status": row["status"],
            "owner_decision": row["owner_decision"],
            "owner_principal": row["owner_principal"],
            "created_at": row["created_at"],
            "decided_at": row["decided_at"],
            "resolved_at": row["resolved_at"],
        }
        return escalation_from_persist(persist_data)


class GovernanceStateStore(SQLiteStore):
    """Persistent governance state storage."""

    def __init__(self, db_path: str) -> None:
        super().__init__(db_path)
        self._init_schema()

    def _init_schema(self) -> None:
        """Create the governance state table."""
        self.execute("""
            CREATE TABLE IF NOT EXISTS governance_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                integrity_hash TEXT NOT NULL
            )
        """)
        self.commit()

    def set(self, key: str, value: Any) -> None:
        """Set a governance state value. Thread-safe: under _lock."""
        value_str = json.dumps(value)
        integrity_hash = sha256_hex(value_str.encode())
        with self._lock:
            self.execute("""
                INSERT OR REPLACE INTO governance_state
                (key, value, updated_at, integrity_hash)
                VALUES (?, ?, ?, ?)
            """, (key, value_str, datetime.now(timezone.utc).isoformat(), integrity_hash))
            self.commit()

    def get(self, key: str) -> Optional[Any]:
        """Get a governance state value. Thread-safe: under _lock."""
        with self._lock:
            result = self.execute(
                "SELECT value FROM governance_state WHERE key = ?",
                (key,)
            )
            row = result.fetchone()
        if row is None:
            return None
        return json.loads(row["value"])

    def verify_integrity(self) -> bool:
        """Verify integrity of all governance state entries. Thread-safe: under _lock."""
        with self._lock:
            result = self.execute("SELECT * FROM governance_state")
            rows = result.fetchall()
        for row in rows:
            expected_hash = sha256_hex(row["value"].encode())
            if row["integrity_hash"] != expected_hash:
                return False
        return True
