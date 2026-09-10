"""AxiomGate Kernel — Escalation State Machine

Authoritative mutation is Mediator-only.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional
import threading

from .domain import EscalationStatus


class EscalationError(Exception):
    """Raised when escalation operations fail."""
    pass


@dataclass(frozen=True)
class EscalationRecord:
    """Immutable escalation record."""
    escalation_id: str
    request_id: str
    principal_id: str
    payload_hash: str
    reason: str
    reason_class: str
    status: EscalationStatus
    owner_decision: Optional[str] = None
    owner_principal: Optional[str] = None
    created_at: str = ""
    decided_at: Optional[str] = None
    resolved_at: Optional[str] = None


class EscalationStore:
    """Thread-safe escalation store.

    decide/resolve are for Mediator, not requestors.
    """

    def __init__(self) -> None:
        self._items: Dict[str, EscalationRecord] = {}
        self._lock = threading.Lock()

    def create(
        self,
        escalation_id: str,
        request_id: str,
        principal_id: str,
        payload_hash: str,
        reason: str,
        reason_class: str,
    ) -> EscalationRecord:
        """Create a new escalation record."""
        with self._lock:
            if escalation_id in self._items:
                raise EscalationError("escalation exists")
            record = EscalationRecord(
                escalation_id=escalation_id,
                request_id=request_id,
                principal_id=principal_id,
                payload_hash=payload_hash,
                reason=reason,
                reason_class=reason_class,
                status=EscalationStatus.PENDING,
                created_at=_now(),
            )
            self._items[escalation_id] = record
            return record

    def get(self, escalation_id: str) -> Optional[EscalationRecord]:
        """Get an escalation record. Returns frozen record."""
        with self._lock:
            return self._items.get(escalation_id)

    def mediator_decide(self, escalation_id: str, decision: str, owner_principal: str) -> EscalationRecord:
        """Owner decides on an escalation. Mediator-only."""
        if decision not in ("permit", "deny"):
            raise EscalationError("invalid owner decision")
        with self._lock:
            record = self._items.get(escalation_id)
            if record is None:
                raise EscalationError("escalation not found")
            if record.status is not EscalationStatus.PENDING:
                raise EscalationError("escalation not pending")
            new = EscalationRecord(
                escalation_id=record.escalation_id,
                request_id=record.request_id,
                principal_id=record.principal_id,
                payload_hash=record.payload_hash,
                reason=record.reason,
                reason_class=record.reason_class,
                status=EscalationStatus.DECIDED,
                owner_decision=decision,
                owner_principal=owner_principal,
                created_at=record.created_at,
                decided_at=_now(),
            )
            self._items[escalation_id] = new
            return new

    def mediator_resolve(self, escalation_id: str) -> EscalationRecord:
        """Resolve an escalation after grant consumption. Mediator-only."""
        with self._lock:
            record = self._items.get(escalation_id)
            if record is None:
                raise EscalationError("escalation not found")
            if record.status is EscalationStatus.PENDING:
                raise EscalationError("cannot resolve before decide")
            if record.status is not EscalationStatus.DECIDED:
                raise EscalationError("escalation not decided")
            new = EscalationRecord(
                escalation_id=record.escalation_id,
                request_id=record.request_id,
                principal_id=record.principal_id,
                payload_hash=record.payload_hash,
                reason=record.reason,
                reason_class=record.reason_class,
                status=EscalationStatus.RESOLVED,
                owner_decision=record.owner_decision,
                owner_principal=record.owner_principal,
                created_at=record.created_at,
                decided_at=record.decided_at,
                resolved_at=_now(),
            )
            self._items[escalation_id] = new
            return new


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
