"""AxiomGate Kernel — Reserved Grant

One-shot reserved Owner grant with 12-field binding.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, Optional
from uuid import uuid4
import threading

from .domain import ActionType, RiskLevel


class ReasonClass(Enum):
    """Reason for escalation."""
    OWNER_MANDATORY_ACTION = "owner_mandatory_action"
    OWNER_MANDATORY_RISK = "owner_mandatory_risk"
    POLICY = "policy"
    PROVENANCE = "provenance"
    OTHER = "other"


class GrantError(Exception):
    """Raised when grant operations fail."""
    pass


@dataclass(frozen=True)
class ReservedGrant:
    """One-shot reserved grant with 12-field binding."""
    grant_id: str
    escalation_id: str
    principal_id: str
    agent_id: str
    request_id: str
    action: str
    domain: str
    risk_level: str
    payload_hash: str
    capability_id: str
    capability_scope_hash: str
    policy_version: str
    policy_hash: str
    provenance_kind: str
    provenance_identity: str
    reason_class: ReasonClass
    owner_decision: str
    created_at: str
    expires_at: str
    consumed: bool


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ReservedGrantStore:
    """Thread-safe reserved grant store."""

    def __init__(self, ttl: Optional[timedelta] = None) -> None:
        self._items: Dict[str, ReservedGrant] = {}
        self._by_escalation: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._ttl = ttl or timedelta(hours=1)

    def create_pending_context(
        self,
        *,
        escalation_id: str,
        principal_id: str,
        agent_id: str,
        request_id: str,
        action: str,
        domain: str,
        risk_level: str,
        payload_hash: str,
        capability_id: str,
        capability_scope_hash: str,
        policy_version: str,
        policy_hash: str,
        provenance_kind: str,
        provenance_identity: str,
        reason_class: ReasonClass,
    ) -> None:
        """Remember evaluate-time binding; Owner decide later fills owner_decision."""
        with self._lock:
            gid = f"rg-{uuid4().hex[:12]}"
            now = _now()
            grant = ReservedGrant(
                grant_id=gid,
                escalation_id=escalation_id,
                principal_id=principal_id,
                agent_id=agent_id,
                request_id=request_id,
                action=action,
                domain=domain,
                risk_level=risk_level,
                payload_hash=payload_hash,
                capability_id=capability_id,
                capability_scope_hash=capability_scope_hash,
                policy_version=policy_version,
                policy_hash=policy_hash,
                provenance_kind=provenance_kind,
                provenance_identity=provenance_identity,
                reason_class=reason_class,
                owner_decision="",
                created_at=now.isoformat(),
                expires_at=(now + self._ttl).isoformat(),
                consumed=False,
            )
            self._items[gid] = grant
            self._by_escalation[escalation_id] = gid

    def attach_owner_decision(self, escalation_id: str, decision: str) -> Optional[ReservedGrant]:
        """Attach Owner decision to a pending grant."""
        with self._lock:
            gid = self._by_escalation.get(escalation_id)
            if gid is None:
                return None
            old = self._items[gid]
            new = ReservedGrant(
                **{**old.__dict__, "owner_decision": decision},
            )
            self._items[gid] = new
            return new

    def get_by_escalation(self, escalation_id: str) -> Optional[ReservedGrant]:
        """Get grant by escalation ID."""
        with self._lock:
            gid = self._by_escalation.get(escalation_id)
            if gid is None:
                return None
            return self._items.get(gid)

    def consume_if_valid(
        self,
        escalation_id: str,
        *,
        principal_id: str,
        agent_id: str,
        request_id: str,
        action: str,
        domain: str,
        risk_level: str,
        payload_hash: str,
        capability_id: str,
        capability_scope_hash: str,
        policy_hash: str,
        provenance_identity: str,
    ) -> ReservedGrant:
        """Atomically consume a matching unused grant. Fail closed on any mismatch."""
        with self._lock:
            gid = self._by_escalation.get(escalation_id)
            if gid is None:
                raise GrantError("no reserved grant")
            grant = self._items[gid]
            if grant.consumed:
                raise GrantError("grant already consumed")
            if grant.owner_decision != "permit":
                raise GrantError("no owner permit on grant")
            now = _now()
            try:
                exp = datetime.fromisoformat(grant.expires_at)
            except ValueError as exc:
                raise GrantError("grant expiry corrupt") from exc
            if now >= exp:
                raise GrantError("grant expired")
            checks = {
                "principal": (grant.principal_id, principal_id),
                "agent_id": (grant.agent_id, agent_id),
                "request_id": (grant.request_id, request_id),
                "action": (grant.action, action),
                "domain": (grant.domain, domain),
                "risk": (grant.risk_level, risk_level),
                "payload": (grant.payload_hash, payload_hash),
                "capability_id": (grant.capability_id, capability_id),
                "capability_scope": (grant.capability_scope_hash, capability_scope_hash),
            }
            # For POLICY and PROVENANCE reason classes, skip the corresponding check
            if grant.reason_class is not ReasonClass.POLICY:
                checks["policy"] = (grant.policy_hash, policy_hash)
            if grant.reason_class is not ReasonClass.PROVENANCE:
                checks["provenance"] = (grant.provenance_identity, provenance_identity)

            if grant.reason_class in (ReasonClass.POLICY, ReasonClass.PROVENANCE):
                # En policy- eller provenansandring ar ofta samma handelse som
                # en omutfardad kapabilitet: agaren ratar upp laget och ger ut
                # nya id:n. Att binda grantet mot det gamla kapabilitets-id:t
                # skulle da ogiltigforklara precis det agaren just godkande.
                # Det gor inte om behorighetsprovningen: mediator.reenter kor
                # check_capability mot registret pa nytt och kraver ALLOW innan
                # den ens anropar hit. Det som slapps ar bindningen till en
                # specifik kapabilitet, inte kravet pa att ha en giltig.
                checks.pop("capability_id", None)
                checks.pop("capability_scope", None)

            for name, (expected, actual) in checks.items():
                if expected != actual:
                    raise GrantError(f"grant binding mismatch: {name}")
            consumed = ReservedGrant(**{**grant.__dict__, "consumed": True})
            self._items[gid] = consumed
            return consumed

    def unconsume(self, escalation_id: str) -> None:
        """Atomically roll back grant consumption if downstream audit logging fails."""
        with self._lock:
            gid = self._by_escalation.get(escalation_id)
            if gid is not None and gid in self._items:
                grant = self._items[gid]
                if grant.consumed:
                    restored = ReservedGrant(**{**grant.__dict__, "consumed": False})
                    self._items[gid] = restored


def scope_hash(capability) -> str:
    """Compute scope hash for a capability."""
    from .canonical import canonical_json
    from .crypto import sha256_hex
    body = {
        "capability_id": capability.capability_id,
        "principal_id": capability.principal_id,
        "domains": sorted(capability.domains),
        "action_types": sorted(a.value for a in capability.action_types),
        "risk_ceiling": capability.risk_ceiling.value,
        "role": capability.role.value,
    }
    return sha256_hex(canonical_json(body).encode("utf-8"))
