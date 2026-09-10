"""AxiomGate Kernel — Principal Context Propagation

ContextVar-based principal identity that flows through agent execution.
Every tool call can read this context to determine WHO is requesting execution.

WIRED since 2026-09-10, behind an opt-in flag. `authorization.check_capability`
reads the bound context when the Mediator was constructed with
`require_principal_context=True`, and the effective risk ceiling is then
`min(capability.risk_ceiling, mandate ceiling)`. A missing or invalid context
is a DENY, never a fallback to the most permissive value.

**With the flag off -- the default -- nothing here bounds a verdict.** That is
a declared gap, not a hidden one: turning it on by default would deny every
request at every existing integrator, since no context would be bound. See
docs/ROADMAP.md, item R1, for the exact terms and what is still not covered.

Usage:
    from axiomgate_kernel.principal_context import (
        PrincipalContext,
        get_principal_context,
        set_principal_context,
        clear_principal_context,
        principal_context_scope,
    )

    # Set context when session starts
    ctx = PrincipalContext(
        principal_id="agent:session:abc123",
        parent_principal_id="owner:<configured-owner-id>",
        session_id="abc123",
        mandate=None,
        provenance="direct",
    )
    set_principal_context(ctx)

    # Read context in invoke_tool
    ctx = get_principal_context()
    if ctx is None:
        # No principal bound — fail closed for governed mutations
        ...
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass, field
import hashlib
from datetime import datetime, timezone
from typing import Optional, FrozenSet
from contextlib import contextmanager

from .domain import ActionType, RiskLevel


@dataclass(frozen=True)
class PrincipalContext:
    """Immutable principal context for a tool invocation.

    Attributes:
        principal_id: Who is requesting execution (e.g., "agent:session:abc123")
        parent_principal_id: Who authorized this agent (e.g., "owner:<configured-owner-id>")
        session_id: Host session ID
        mandate: Bounded scope from Owner (None = no mandate, must escalate)
        provenance: How this execution originated (direct|delegated|cron|mcp)
        subagent_id: If delegated, the child's ID (None for direct execution)
        parent_session_id: If delegated, the parent's session ID
        cron_job_id: If cron-triggered, the job ID (None otherwise)
    """
    principal_id: str
    parent_principal_id: Optional[str] = None
    session_id: Optional[str] = None
    mandate: Optional[str] = None
    provenance: str = "direct"  # direct | delegated | cron | mcp
    subagent_id: Optional[str] = None
    parent_session_id: Optional[str] = None
    cron_job_id: Optional[str] = None


# The ContextVar that flows through all execution
PrincipalContextType: ContextVar[Optional[PrincipalContext]] = ContextVar(
    "axiomgate_principal_context",
    default=None,
)


def get_principal_context() -> Optional[PrincipalContext]:
    """Read the current principal context. Returns None if not set."""
    return PrincipalContextType.get()


def set_principal_context(ctx: PrincipalContext) -> Token:
    """Set the principal context. Returns a Token for restore."""
    return PrincipalContextType.set(ctx)


def clear_principal_context() -> None:
    """Clear the principal context."""
    PrincipalContextType.set(None)


@contextmanager
def principal_context_scope(ctx: PrincipalContext):
    """Context manager that sets principal context and restores on exit."""
    token = set_principal_context(ctx)
    try:
        yield
    finally:
        PrincipalContextType.reset(token)


def propagate_for_subagent(
    parent_ctx: Optional[PrincipalContext],
    subagent_id: str,
    child_session_id: str,
    mandate: Optional[str] = None,
) -> PrincipalContext:
    """Create a child principal context from a parent.

    The child inherits the parent's principal_id and parent_principal_id.
    The child's own principal_id is derived from the parent's session + subagent_id.
    The child's mandate MUST be a subset of the parent's mandate.
    """
    if parent_ctx is None:
        # No parent context — subagent has no principal binding
        return PrincipalContext(
            principal_id=f"subagent:{subagent_id}",
            session_id=child_session_id,
            mandate=mandate,
            provenance="delegated",
            subagent_id=subagent_id,
        )

    # Enforce subset constraint: child mandate must be ⊆ parent mandate
    effective_mandate = mandate or parent_ctx.mandate
    if effective_mandate and parent_ctx.mandate:
        parent_mandate = parse_mandate(parent_ctx.mandate)
        child_mandate = parse_mandate(effective_mandate)
        if parent_mandate and child_mandate:
            if not child_mandate.is_subset_of(parent_mandate):
                # Child mandate is broader than parent — BLOCK by using parent mandate
                # This ensures child cannot exceed parent authority
                effective_mandate = parent_ctx.mandate

    return PrincipalContext(
        principal_id=f"subagent:{subagent_id}",
        parent_principal_id=parent_ctx.principal_id,
        session_id=child_session_id,
        mandate=effective_mandate,
        provenance="delegated",
        subagent_id=subagent_id,
        parent_session_id=parent_ctx.session_id,
        cron_job_id=parent_ctx.cron_job_id,
    )


def propagate_for_cron(
    job_id: str,
    owner_principal_id: str,
    session_id: str,
    mandate: str,
) -> PrincipalContext:
    """Create a principal context for a cron-triggered execution.

    Cron jobs MUST have a pre-registered mandate.
    """
    return PrincipalContext(
        principal_id=f"cron:{job_id}",
        parent_principal_id=owner_principal_id,
        session_id=session_id,
        mandate=mandate,
        provenance="cron",
        cron_job_id=job_id,
    )


def is_principal_valid(ctx: Optional[PrincipalContext]) -> bool:
    """Check if principal context is present and has a valid identity."""
    if ctx is None:
        return False
    if not ctx.principal_id:
        return False
    return True


def is_mandate_valid(ctx: Optional[PrincipalContext], required_for_mutation: bool = True) -> bool:
    """Check if mandate is valid for the requested operation.

    Read-only operations don't require a mandate.
    Mutations require a mandate unless explicitly exempted.
    """
    if not required_for_mutation:
        return True
    if ctx is None:
        return False
    return ctx.mandate is not None and ctx.mandate != ""


# ============================================================
# Mandate Model — machine-checkable scope enforcement
# ============================================================

# Valid mandate scopes: maps to AxiomGate Kernel action_types
MANDATE_SCOPES = {
    "read-only": frozenset({ActionType.INSPECT}),
    "inspect": frozenset({ActionType.INSPECT}),
    "propose": frozenset({ActionType.INSPECT, ActionType.PROPOSE}),
    "verify": frozenset({ActionType.INSPECT, ActionType.PROPOSE, ActionType.VERIFY}),
    "execute": frozenset({ActionType.INSPECT, ActionType.PROPOSE, ActionType.VERIFY, ActionType.EXECUTE}),
    "full": frozenset({ActionType.INSPECT, ActionType.PROPOSE, ActionType.VERIFY, ActionType.EXECUTE}),
    # COMMIT is always Owner-mandatory, never delegated
}

# Risk ceilings per mandate scope
MANDATE_RISK_CEILING = {
    "read-only": RiskLevel.LOW,
    "inspect": RiskLevel.LOW,
    "propose": RiskLevel.LOW,
    "verify": RiskLevel.MEDIUM,
    "execute": RiskLevel.MEDIUM,
    "full": RiskLevel.HIGH,
}


@dataclass(frozen=True)
class Mandate:
    """Machine-checkable mandate scope.

    Maps directly to AxiomGate Kernel capability fields:
    - scope determines action_types
    - scope determines risk_ceiling
    - expires_at provides temporal validity
    """
    mandate_id: str
    scope: str  # Must be a key in MANDATE_SCOPES
    expires_at: Optional[datetime] = None
    parent_mandate_id: Optional[str] = None  # For delegation tracking

    @property
    def action_types(self) -> frozenset:
        """Action types authorized by this mandate."""
        return MANDATE_SCOPES.get(self.scope, frozenset())

    @property
    def risk_ceiling(self) -> RiskLevel:
        """Maximum risk level authorized by this mandate."""
        return MANDATE_RISK_CEILING.get(self.scope, RiskLevel.LOW)

    @property
    def is_valid(self) -> bool:
        """Check if mandate is structurally valid."""
        if not self.scope or self.scope not in MANDATE_SCOPES:
            return False
        if self.expires_at and self.expires_at < datetime.now(timezone.utc):
            return False
        return True

    @property
    def is_expired(self) -> bool:
        """Check if mandate has expired."""
        if self.expires_at is None:
            return False
        return self.expires_at < datetime.now(timezone.utc)

    def is_subset_of(self, other: "Mandate") -> bool:
        """Check if this mandate's authority is a subset of another's."""
        if not other or not other.is_valid:
            return False
        return (
            self.action_types <= other.action_types
            and self.risk_ceiling.rank <= other.risk_ceiling.rank
        )

    def allows_action(self, action: ActionType, risk: RiskLevel) -> bool:
        """Check if this mandate allows a specific action at a risk level."""
        if not self.is_valid:
            return False
        if action not in self.action_types:
            return False
        if risk.rank > self.risk_ceiling.rank:
            return False
        return True


def parse_mandate(mandate_str: str) -> Optional[Mandate]:
    """Parse a mandate string into a structured Mandate object.

    Supports formats:
    - "scope" (e.g., "read-only", "execute", "full")
    - "scope:expires:ISO8601" (e.g., "execute:expires:2026-12-31T23:59:59Z")
    - "scope:expires:ISO8601:parent:ID" (delegation chain)

    Allt annat avvisas. En svans som inte känns igen får aldrig ignoreras tyst:
    ett mandat som ser tidsbegränsat ut men tappar sin utgång är fail-open.
    """
    if not mandate_str or not isinstance(mandate_str, str):
        return None

    head, sep, rest = mandate_str.partition(":")
    scope = head.strip().lower()

    if scope not in MANDATE_SCOPES:
        return None

    expires_at = None
    parent_mandate_id = None

    if sep:
        # Delas inte på ":" — ISO 8601-tidstämpeln bär egna kolon, och en
        # naiv split styckade den till "2026-12-31T23" (23:00 i stället för
        # 23:59:59) och sköt samtidigt parent-nyckeln ur sitt index.
        if not rest.startswith("expires:"):
            return None
        tail = rest[len("expires:"):]
        ts_str, parent_sep, parent_id = tail.partition(":parent:")
        if parent_sep:
            if not parent_id or ":" in parent_id:
                return None
            parent_mandate_id = parent_id
        try:
            expires_at = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except ValueError:
            return None  # Malformed expiry
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

    # sha256, inte hash(): den inbyggda hashen randomiseras per process, så
    # samma mandatsträng fick olika id i två körningar och kunde varken
    # korsrefereras i audit-loggen eller matchas mot parent_mandate_id.
    digest = hashlib.sha256(mandate_str.encode("utf-8")).hexdigest()[:8]
    mandate_id = f"mandate-{scope}-{digest}"

    return Mandate(
        mandate_id=mandate_id,
        scope=scope,
        expires_at=expires_at,
        parent_mandate_id=parent_mandate_id,
    )
