"""AxiomGate Kernel — Persistence Serializers

Explicit serialization/deserialization for domain objects.
Keeps domain model pure (no persistence awareness).
Ensures deterministic, semantically lossless round-trips.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .domain import ActionType, EvidenceState, EscalationStatus, RiskLevel, Role


def _serialize_enum(obj) -> str:
    """Serialize an enum to its string value."""
    if hasattr(obj, "value"):
        return obj.value
    return str(obj)


def _serialize_datetime(obj) -> Optional[str]:
    """Serialize a datetime to ISO format string."""
    if obj is None:
        return None
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return str(obj)


def _serialize_frozenset_sorted(obj, key_func=None) -> list:
    """Serialize a frozenset to a sorted list."""
    if key_func:
        return sorted(obj, key=key_func)
    return sorted(obj, key=str)


def _deserialize_enum(value: str, enum_class):
    """Deserialize a string to an enum value."""
    return enum_class(value)


def _deserialize_datetime(value: Optional[str]) -> Optional[datetime]:
    """Deserialize an ISO string to a datetime."""
    if value is None:
        return None
    return datetime.fromisoformat(value)


# --- Capability Serialization ---

def capability_to_persist(cap) -> Dict[str, Any]:
    """Convert a Capability to a deterministic persistence representation.

    Security-relevant fields:
    - capability_id: str
    - principal_id: str
    - role: Role (serialized as string value)
    - domains: FrozenSet[str] (serialized as sorted list)
    - action_types: FrozenSet[ActionType] (serialized as sorted list of string values)
    - risk_ceiling: RiskLevel (serialized as string value)
    - issued_by: str
    - issued_at: datetime (serialized as ISO string)
    - expires_at: datetime (serialized as ISO string)
    - transferable: bool
    - delegation_depth: int
    - revoked_at: Optional[datetime] (serialized as ISO string)
    """
    return {
        "capability_id": cap.capability_id,
        "principal_id": cap.principal_id,
        "role": _serialize_enum(cap.role),
        "domains": sorted(cap.domains),
        "action_types": sorted([_serialize_enum(a) for a in cap.action_types]),
        "risk_ceiling": _serialize_enum(cap.risk_ceiling),
        "issued_by": cap.issued_by,
        "issued_at": _serialize_datetime(cap.issued_at),
        "expires_at": _serialize_datetime(cap.expires_at),
        "transferable": cap.transferable,
        "delegation_depth": cap.delegation_depth,
        "revoked_at": _serialize_datetime(cap.revoked_at),
    }


def capability_from_persist(data: Dict[str, Any]):
    """Reconstruct a Capability from persistence representation.

    Returns a fully validated Capability instance.
    Raises ValueError if the persisted data is invalid.
    """
    from .capability import Capability

    return Capability(
        capability_id=data["capability_id"],
        principal_id=data["principal_id"],
        role=_deserialize_enum(data["role"], Role),
        domains=frozenset(data["domains"]),
        action_types=frozenset([_deserialize_enum(a, ActionType) for a in data["action_types"]]),
        risk_ceiling=_deserialize_enum(data["risk_ceiling"], RiskLevel),
        issued_by=data["issued_by"],
        issued_at=_deserialize_datetime(data["issued_at"]),
        expires_at=_deserialize_datetime(data["expires_at"]),
        transferable=data["transferable"],
        delegation_depth=data["delegation_depth"],
        revoked_at=_deserialize_datetime(data.get("revoked_at")),
    )


# --- Evidence Serialization ---

def evidence_to_persist(record) -> Dict[str, Any]:
    """Convert an EvidenceRecord to persistence representation."""
    return {
        "evidence_id": record.evidence_id,
        "producer_id": record.producer_id,
        "state": _serialize_enum(record.state),
        "content": record.content,
        "verification_result": record.verification_result,
        "verifier_id": record.verifier_id,
        "authorization_result": record.authorization_result,
        "authorizer_id": record.authorizer_id,
    }


def evidence_from_persist(data: Dict[str, Any]):
    """Reconstruct an EvidenceRecord from persistence representation."""
    from .evidence import EvidenceRecord

    return EvidenceRecord(
        evidence_id=data["evidence_id"],
        producer_id=data["producer_id"],
        state=_deserialize_enum(data["state"], EvidenceState),
        content=data["content"],
        verification_result=data.get("verification_result"),
        verifier_id=data.get("verifier_id"),
        authorization_result=data.get("authorization_result"),
        authorizer_id=data.get("authorizer_id"),
    )


# --- Escalation Serialization ---

def escalation_to_persist(record) -> Dict[str, Any]:
    """Convert an EscalationRecord to persistence representation."""
    return {
        "escalation_id": record.escalation_id,
        "request_id": record.request_id,
        "principal_id": record.principal_id,
        "payload_hash": record.payload_hash,
        "reason": record.reason,
        "reason_class": record.reason_class,
        "status": record.status.value if hasattr(record.status, "value") else record.status,
        "owner_decision": record.owner_decision,
        "owner_principal": record.owner_principal,
        "created_at": record.created_at,
        "decided_at": record.decided_at,
        "resolved_at": record.resolved_at,
    }


def escalation_from_persist(data: Dict[str, Any]):
    """Reconstruct an EscalationRecord from persistence representation."""
    from .escalation import EscalationRecord

    return EscalationRecord(
        escalation_id=data["escalation_id"],
        request_id=data["request_id"],
        principal_id=data["principal_id"],
        payload_hash=data["payload_hash"],
        reason=data["reason"],
        reason_class=data["reason_class"],
        status=EscalationStatus(data["status"]),
        owner_decision=data.get("owner_decision"),
        owner_principal=data.get("owner_principal"),
        created_at=data["created_at"],
        decided_at=data.get("decided_at"),
        resolved_at=data.get("resolved_at"),
    )


# --- Decision Audit Record Serialization ---

def audit_record_to_persist(record: Dict[str, Any]) -> Dict[str, Any]:
    """Convert an audit record dict to a deterministic persistence representation.

    Ensures consistent field ordering and type conversion for hashing.
    """
    return {
        "timestamp": record.get("timestamp", ""),
        "request_id": record.get("request_id", ""),
        "bound_principal": record.get("bound_principal", ""),
        "agent_id_claim": record.get("agent_id_claim", ""),
        "action_type": record.get("action_type", ""),
        "domain": record.get("domain", ""),
        "risk_level": record.get("risk_level", ""),
        "verdict": record.get("verdict", ""),
        "reason": record.get("reason", ""),
        "applied_rules": sorted(record.get("applied_rules", [])),
        "escalation_id": record.get("escalation_id", ""),
        "owner_decision": record.get("owner_decision", ""),
        "execution_granted": record.get("execution_granted", False),
        "payload_hash": record.get("payload_hash", ""),
    }
