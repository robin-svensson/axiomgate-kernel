"""AxiomGate Kernel — Evidence Lifecycle

Append-only evidence journal with producer separation.
"""

import copy
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional

from .principal import Principal
from .domain import EvidenceState, OWNER_PRINCIPAL_ID, Role


class EvidenceError(Exception):
    """Raised when evidence operations fail."""
    pass


@dataclass(frozen=True)
class EvidenceRecord:
    """Immutable evidence record."""
    evidence_id: str
    producer_id: str
    state: EvidenceState
    content: Any
    verification_result: Optional[bool] = None
    verifier_id: Optional[str] = None
    authorization_result: Optional[bool] = None
    authorizer_id: Optional[str] = None
    # The content digest the record binds. Set once via bind_digest and then
    # carried unchanged through verify/authorize, so that what gets written
    # out as "evidence_digest" is actually tied to the evidence chain.
    digest: Optional[str] = None


@dataclass(frozen=True)
class EvidenceEvent:
    """Append-only evidence event."""
    evidence_id: str
    event: str
    state: str
    actor: str
    timestamp: str
    detail: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "detail", MappingProxyType(dict(self.detail)))


def _require_bool(value: Any, name: str) -> bool:
    """Require a boolean value."""
    if value is True:
        return True
    if value is False:
        return False
    raise EvidenceError(f"{name} must be boolean True or False")


def _detached_record(record: EvidenceRecord) -> EvidenceRecord:
    """Return a detached copy of an evidence record."""
    return EvidenceRecord(
        evidence_id=record.evidence_id,
        producer_id=record.producer_id,
        state=record.state,
        content=copy.deepcopy(record.content),
        verification_result=record.verification_result,
        verifier_id=record.verifier_id,
        authorization_result=record.authorization_result,
        authorizer_id=record.authorizer_id,
        digest=record.digest,
    )


class EvidenceJournal:
    """Thread-safe evidence lifecycle manager.

    Transitions: CANDIDATE → VERIFIED → AUTHORIZED
    Producer cannot verify or authorize own evidence. This is a runtime check
    on principals, not a formal result -- see docs/TRACEABILITY.md.
    Append-only (no retraction).
    """

    def __init__(self) -> None:
        self._events: List[EvidenceEvent] = []
        self._current: Dict[str, EvidenceRecord] = {}
        self._lock = threading.Lock()

    def events(self) -> List[EvidenceEvent]:
        """Get all evidence events. Thread-safe snapshot."""
        with self._lock:
            return [
                EvidenceEvent(e.evidence_id, e.event, e.state, e.actor, e.timestamp, dict(e.detail))
                for e in self._events
            ]

    def get(self, evidence_id: str) -> Optional[EvidenceRecord]:
        """Get current evidence record. Returns detached copy."""
        with self._lock:
            rec = self._current.get(evidence_id)
            return _detached_record(rec) if rec is not None else None

    def create_candidate(self, evidence_id: str, producer_id: str, content: Any) -> EvidenceRecord:
        """Create candidate evidence."""
        if not isinstance(producer_id, str) or not producer_id:
            raise EvidenceError("producer_id must be str")
        stored_content = copy.deepcopy(content)
        with self._lock:
            if evidence_id in self._current:
                raise EvidenceError("evidence id already exists")
            record = EvidenceRecord(evidence_id, producer_id, EvidenceState.CANDIDATE, stored_content)
            self._current[evidence_id] = record
            self._events.append(
                EvidenceEvent(evidence_id, "create_candidate", EvidenceState.CANDIDATE.value, producer_id, _now())
            )
            return _detached_record(record)

    def bind_digest(self, evidence_id: str, digest: str, actor: str) -> EvidenceRecord:
        """Bind a content digest to candidate evidence. Once only.

        A digest that can be replaced after the fact binds nothing, so a second
        call raises rather than overwriting. Binding is only allowed while the
        evidence is still a candidate: after verification the verifier has
        already attested to what the record held.
        """
        if not isinstance(digest, str) or not digest:
            raise EvidenceError("digest must be a non-empty str")
        if not isinstance(actor, str) or not actor:
            raise EvidenceError("actor must be str")
        with self._lock:
            record = self._require(evidence_id)
            if record.digest is not None:
                raise EvidenceError("digest already bound")
            if record.state is not EvidenceState.CANDIDATE:
                raise EvidenceError(f"cannot bind digest from {record.state.value}")
            new = EvidenceRecord(
                evidence_id=record.evidence_id,
                producer_id=record.producer_id,
                state=record.state,
                content=record.content,
                verification_result=record.verification_result,
                verifier_id=record.verifier_id,
                authorization_result=record.authorization_result,
                authorizer_id=record.authorizer_id,
                digest=digest,
            )
            self._current[evidence_id] = new
            self._events.append(
                EvidenceEvent(
                    evidence_id, "digest_bound", record.state.value,
                    actor, _now(), {"digest": digest},
                )
            )
            return _detached_record(new)

    def verify(
        self,
        evidence_id: str,
        principal: Principal,
        role: Role,
        result: Any,
    ) -> EvidenceRecord:
        """Verify evidence. Requires R-IV and different principal."""
        ok = _require_bool(result, "verification_result")
        with self._lock:
            record = self._require(evidence_id)
            if record.state is not EvidenceState.CANDIDATE:
                raise EvidenceError(f"cannot verify from {record.state.value}")
            if not isinstance(principal.principal_id, str):
                raise EvidenceError("invalid principal")
            if principal.principal_id == record.producer_id:
                raise EvidenceError("producer cannot verify own evidence")
            if role is not Role.R_IV:
                raise EvidenceError("verification requires R-IV")
            if ok:
                new = EvidenceRecord(
                    evidence_id=record.evidence_id,
                    producer_id=record.producer_id,
                    state=EvidenceState.VERIFIED,
                    content=record.content,
                    verification_result=True,
                    verifier_id=principal.principal_id,
                    digest=record.digest,
                )
                self._current[evidence_id] = new
                self._events.append(
                    EvidenceEvent(
                        evidence_id, "verified", EvidenceState.VERIFIED.value,
                        principal.principal_id, _now(), {"result": True},
                    )
                )
                return _detached_record(new)
            new = EvidenceRecord(
                evidence_id=record.evidence_id,
                producer_id=record.producer_id,
                state=EvidenceState.CANDIDATE,
                content=record.content,
                verification_result=False,
                verifier_id=principal.principal_id,
                digest=record.digest,
            )
            self._current[evidence_id] = new
            self._events.append(
                EvidenceEvent(
                    evidence_id, "verification_failed", EvidenceState.CANDIDATE.value,
                    principal.principal_id, _now(), {"result": False},
                )
            )
            return _detached_record(new)

    def authorize(
        self,
        evidence_id: str,
        principal: Principal,
        role: Role,
        result: Any,
    ) -> EvidenceRecord:
        """Authorize evidence. Requires R-DEC Owner, verified state, different principal."""
        ok = _require_bool(result, "authorization_result")
        with self._lock:
            record = self._require(evidence_id)
            if role is Role.R_IV:
                raise EvidenceError("R-IV cannot authorize evidence")
            if principal.principal_id != OWNER_PRINCIPAL_ID or role is not Role.R_DEC:
                raise EvidenceError("authorization requires Owner principal with R-DEC")
            if principal.principal_id == record.producer_id:
                raise EvidenceError("producer cannot be final authority")
            if record.state is not EvidenceState.VERIFIED:
                raise EvidenceError(f"cannot authorize from {record.state.value}")
            if record.verification_result is not True:
                raise EvidenceError("cannot authorize unverified evidence")
            if ok:
                new = EvidenceRecord(
                    evidence_id=record.evidence_id,
                    producer_id=record.producer_id,
                    state=EvidenceState.AUTHORIZED,
                    content=record.content,
                    verification_result=record.verification_result,
                    verifier_id=record.verifier_id,
                    authorization_result=True,
                    authorizer_id=principal.principal_id,
                    digest=record.digest,
                )
                self._current[evidence_id] = new
                self._events.append(
                    EvidenceEvent(
                        evidence_id, "authorized", EvidenceState.AUTHORIZED.value,
                        principal.principal_id, _now(), {"result": True},
                    )
                )
                return _detached_record(new)
            new = EvidenceRecord(
                evidence_id=record.evidence_id,
                producer_id=record.producer_id,
                state=EvidenceState.VERIFIED,
                content=record.content,
                verification_result=record.verification_result,
                verifier_id=record.verifier_id,
                authorization_result=False,
                authorizer_id=principal.principal_id,
                digest=record.digest,
            )
            self._current[evidence_id] = new
            self._events.append(
                EvidenceEvent(
                    evidence_id, "authorization_failed", EvidenceState.VERIFIED.value,
                    principal.principal_id, _now(), {"result": False},
                )
            )
            return _detached_record(new)

    def _require(self, evidence_id: str) -> EvidenceRecord:
        """Get evidence or raise."""
        record = self._current.get(evidence_id)
        if record is None:
            raise EvidenceError("evidence not found")
        return record


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
