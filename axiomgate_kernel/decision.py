"""AxiomGate Kernel — Decision Model

Mediator decision returned to a caller. PERMIT is the only execution grant.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .domain import Verdict


@dataclass
class Decision:
    """Authorization decision from the Mediator.

    PERMIT includes a grant dict and audit_hash.
    DENY includes reason and applied rules.
    ESCALATE includes escalation_id for later reentry.
    """

    verdict: Verdict
    reason: str
    applied_rules: List[str] = field(default_factory=list)
    bound_principal: Optional[str] = None
    grant: Optional[Dict[str, Any]] = None
    escalation_id: Optional[str] = None
    audit_hash: Optional[str] = None
    owner_decision: Optional[str] = None
