"""AxiomGate Kernel — Core Type Definitions

Canonical governance types. These define the vocabulary of the system.
All values are immutable and verified against canonical AxiomGate Kernel invariants.
"""

from enum import Enum


# --- Owner Identity ---

OWNER_PRINCIPAL_ID = "owner"
"""The fixed principal ID for the Owner. Cannot be changed."""

OWNER_MANDATORY_ACTIONS = frozenset({"COMMIT"})
"""Actions that always require Owner decision for non-Owner principals.

Note: DEPLOY was considered but deferred — canonical AxiomGate Kernel does not define it.
If needed, add here after explicit design decision."""

# --- Enums ---


class ActionType(Enum):
    """Actions that agents may request.

    INSPECT: Read-only observation
    PROPOSE: Suggest changes without executing
    EXECUTE: Perform an action
    VERIFY: Verify evidence or results
    COMMIT: Apply changes to persistent state (Owner-mandatory)
    """

    INSPECT = "INSPECT"
    PROPOSE = "PROPOSE"
    EXECUTE = "EXECUTE"
    VERIFY = "VERIFY"
    COMMIT = "COMMIT"


class RiskLevel(Enum):
    """Risk classification for requested actions.

    Numeric rank is the ONLY legal comparison order.
    String comparison is NOT valid for risk ranking.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def rank(self) -> int:
        """Numeric rank for comparison. Higher = more risky."""
        return {
            RiskLevel.LOW: 0,
            RiskLevel.MEDIUM: 1,
            RiskLevel.HIGH: 2,
        }[self]

    def exceeds(self, ceiling: "RiskLevel") -> bool:
        """Check if this risk level exceeds a ceiling."""
        return self.rank > ceiling.rank


class Role(Enum):
    """Agent roles in the governance model.

    R-ENG: Engineering agent (can inspect, propose, execute)
    R-IV: Independent verifier (can inspect, propose, verify)
    R-DEC: Decision authority (Owner only — full authority)
    """

    R_ENG = "R-ENG"
    R_IV = "R-IV"
    R_DEC = "R-DEC"


class Verdict(Enum):
    """Authorization verdicts.

    PERMIT: Action is authorized (execution grant issued)
    DENY: Action is blocked; the action does not happen
    ESCALATE: Action is blocked until Owner decides

    The TLA+ model has no verdict type; its enforcement records carry
    ALLOWED / not-allowed and no third value. Do not map these onto
    invariant numbers -- see docs/TRACEABILITY.md.
    """

    PERMIT = "PERMIT"
    DENY = "DENY"
    ESCALATE = "ESCALATE"


class EvidenceState(Enum):
    """Evidence lifecycle states.

    CANDIDATE: Evidence produced, awaiting verification
    VERIFIED: Evidence verified by independent verifier (R-IV)
    AUTHORIZED: Evidence authorized by Owner (R-DEC)

    Note: FAILED state considered but not added — evidence that fails
    verification simply remains CANDIDATE with verification_result=False.
    If FAILED semantics are needed, add after explicit design decision.
    """

    CANDIDATE = "CANDIDATE"
    VERIFIED = "VERIFIED"
    AUTHORIZED = "AUTHORIZED"


class EscalationStatus(Enum):
    """Escalation lifecycle states.

    PENDING: Awaiting Owner decision
    DECIDED: Owner has decided (permit or deny)
    RESOLVED: Escalation completed (grant consumed or denied)

    Note: TIMEOUT and REJECTED states considered but not added —
    timeout can be implemented via grant expiry, rejection via Owner deny.
    If explicit states are needed, add after explicit design decision.
    """

    PENDING = "pending"
    DECIDED = "decided"
    RESOLVED = "resolved"
