"""AxiomGate Kernel — Capability Model and Registry

Capability records with structural validity checks.
Thread-safe registry with detached copies.
"""

import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, FrozenSet, Iterable, List, Optional

from .provisioning import ProvisioningToken, bind_token, require_token
from .domain import ActionType, OWNER_PRINCIPAL_ID, RiskLevel, Role


def _fs_str(values) -> FrozenSet[str]:
    """Convert to frozen set of strings with validation."""
    if isinstance(values, str):
        raise ValueError("domains must be a collection of strings, not a string")
    out = []
    for item in values:
        if not isinstance(item, str) or not item:
            raise ValueError("domain entries must be non-empty str")
        out.append(item)
    return frozenset(out)


def _fs_actions(values) -> FrozenSet[ActionType]:
    """Convert to frozen set of ActionType with validation."""
    if isinstance(values, str):
        raise ValueError("action_types must be a collection, not a string")
    out = []
    for item in values:
        if isinstance(item, ActionType):
            out.append(item)
        else:
            raise ValueError("action_types must be ActionType enums")
    return frozenset(out)


@dataclass(frozen=True)
class Capability:
    """Immutable capability record.

    A capability grants a principal the right to perform specific actions
    within specific domains, up to a risk ceiling.

    Structural validity is enforced:
    - Must be issued by Owner
    - Must not be transferable
    - Delegation depth must be exactly 1
    - R-DEC role is Owner-only
    """

    capability_id: str
    principal_id: str
    role: Role
    domains: FrozenSet[str]
    action_types: FrozenSet[ActionType]
    risk_ceiling: RiskLevel
    issued_by: str
    issued_at: datetime
    expires_at: datetime
    transferable: bool
    delegation_depth: int
    revoked_at: Optional[datetime] = None

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """Check if capability has expired."""
        clock = now or datetime.now(timezone.utc)
        return clock >= self.expires_at

    def is_revoked(self) -> bool:
        """Check if capability has been revoked."""
        return self.revoked_at is not None

    def is_structurally_valid(self) -> bool:
        """Validate structural properties.

        These checks are independent of time and state.
        They validate the capability was correctly constructed.
        """
        if not isinstance(self.role, Role):
            return False
        if not isinstance(self.risk_ceiling, RiskLevel):
            return False
        if not isinstance(self.domains, frozenset):
            return False
        if any(not isinstance(d, str) for d in self.domains):
            return False
        if not isinstance(self.action_types, frozenset):
            return False
        if any(not isinstance(a, ActionType) for a in self.action_types):
            return False
        if self.issued_by != "Owner":
            return False
        if self.transferable:
            return False
        if self.delegation_depth != 1:
            return False
        if self.role is Role.R_DEC and self.principal_id != OWNER_PRINCIPAL_ID:
            return False
        return True

    def is_active(self, now: Optional[datetime] = None) -> bool:
        """Check if capability is currently active."""
        return self.is_structurally_valid() and not self.is_expired(now) and not self.is_revoked()


def make_capability(
    *,
    capability_id: str,
    principal_id: str,
    role: Role,
    domains: Iterable[str],
    action_types: Iterable[ActionType],
    risk_ceiling: RiskLevel,
    issued_by: str,
    issued_at: datetime,
    expires_at: datetime,
    transferable: bool = False,
    delegation_depth: int = 1,
    revoked_at: Optional[datetime] = None,
) -> Capability:
    """Factory function to create a capability with proper frozen sets."""
    return Capability(
        capability_id=capability_id,
        principal_id=principal_id,
        role=role,
        domains=_fs_str(domains),
        action_types=_fs_actions(action_types),
        risk_ceiling=risk_ceiling,
        issued_by=issued_by,
        issued_at=issued_at,
        expires_at=expires_at,
        transferable=transferable,
        delegation_depth=delegation_depth,
        revoked_at=revoked_at,
    )


class CapabilityRegistry:
    """Thread-safe capability registry.

    Stores capabilities and provides lookup by principal.
    All mutations require a provisioning token.
    Returns detached copies to prevent external mutation.
    """

    def __init__(self, bootstrap: Optional[ProvisioningToken] = None) -> None:
        self._caps: Dict[str, Capability] = {}
        self._sealed = False
        self._bound_id = bootstrap.token_id if bootstrap is not None else None
        self._lock = threading.Lock()

    def register(self, capability: Capability, token: ProvisioningToken) -> None:
        """Register a capability. Requires provisioning token."""
        require_token(token, self._sealed)
        self._bound_id = bind_token(self._bound_id, token)
        if not isinstance(capability.domains, frozenset) or isinstance(capability.domains, str):
            raise ValueError("capability structurally invalid")
        if not capability.is_structurally_valid():
            raise ValueError("capability structurally invalid")
        with self._lock:
            self._caps[capability.capability_id] = capability

    def seal(self, token: ProvisioningToken) -> None:
        """Seal the registry. No more registrations after seal."""
        require_token(token, self._sealed)
        self._bound_id = bind_token(self._bound_id, token)
        self._sealed = True
        token._consume()

    def revoke(self, capability_id: str, token: ProvisioningToken, when: Optional[datetime] = None) -> None:
        """Revoke a capability. Requires provisioning token."""
        require_token(token, self._sealed)
        self._bound_id = bind_token(self._bound_id, token)
        with self._lock:
            cap = self._caps.get(capability_id)
            if cap is None:
                raise KeyError(capability_id)
            now = when or datetime.now(timezone.utc)
            self._caps[capability_id] = Capability(
                capability_id=cap.capability_id,
                principal_id=cap.principal_id,
                role=cap.role,
                domains=cap.domains,
                action_types=cap.action_types,
                risk_ceiling=cap.risk_ceiling,
                issued_by=cap.issued_by,
                issued_at=cap.issued_at,
                expires_at=cap.expires_at,
                transferable=cap.transferable,
                delegation_depth=cap.delegation_depth,
                revoked_at=now,
            )

    def get(self, capability_id: str) -> Optional[Capability]:
        """Get a capability by ID. Returns detached copy."""
        with self._lock:
            cap = self._caps.get(capability_id)
            return _detach(cap) if cap is not None else None

    def for_principal(self, principal_id: str) -> List[Capability]:
        """Get all capabilities for a principal. Returns detached copies."""
        with self._lock:
            return [_detach(c) for c in self._caps.values() if c.principal_id == principal_id]

    def active_for(self, principal_id: str, now: Optional[datetime] = None) -> List[Capability]:
        """Get active capabilities for a principal. Returns detached copies."""
        with self._lock:
            return [_detach(c) for c in self._caps.values()
                    if c.principal_id == principal_id and c.is_active(now)]

    @property
    def sealed(self) -> bool:
        return self._sealed


def _detach(cap: Capability) -> Capability:
    """Return a fresh detached copy of a Capability.

    Prevents mutation of stored originals via returned references.
    """
    return Capability(
        capability_id=cap.capability_id,
        principal_id=cap.principal_id,
        role=cap.role,
        domains=frozenset(cap.domains),
        action_types=frozenset(cap.action_types),
        risk_ceiling=cap.risk_ceiling,
        issued_by=cap.issued_by,
        issued_at=cap.issued_at,
        expires_at=cap.expires_at,
        transferable=cap.transferable,
        delegation_depth=cap.delegation_depth,
        revoked_at=cap.revoked_at,
    )
