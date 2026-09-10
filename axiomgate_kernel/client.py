"""AxiomGate Kernel — Fail-Closed Caller Adapter

No local authorization fallback.
"""

from typing import Optional

from .decision import Decision
from .mediator import Mediator
from .domain import Verdict


class MediatorClient:
    """The only supported way for a requester to obtain a verdict.

    If the Mediator is missing or marked unavailable, returns DENY without
    inspecting capabilities, policy, or evidence.
    """

    def __init__(self, mediator: Optional[Mediator] = None) -> None:
        self._mediator = mediator

    def evaluate(self, request: dict) -> Decision:
        """Evaluate an action request."""
        return self._call("evaluate", request)

    def reenter(self, request: dict) -> Decision:
        """Reenter after Owner decision."""
        return self._call("reenter", request)

    def decide_escalation(self, request: dict) -> Decision:
        """Owner decides on an escalation."""
        return self._call("decide_escalation", request)

    def create_evidence(self, request: dict) -> Decision:
        """Create candidate evidence."""
        return self._call("create_evidence", request)

    def verify_evidence(self, request: dict) -> Decision:
        """Verify evidence."""
        return self._call("verify_evidence", request)

    def authorize_evidence(self, request: dict) -> Decision:
        """Authorize evidence."""
        return self._call("authorize_evidence", request)

    def update_policy(self, request: dict) -> Decision:
        """Owner updates policy."""
        return self._call("update_policy", request)

    def _call(self, method: str, request: dict) -> Decision:
        mediator = self._mediator
        if mediator is None or not mediator.available:
            return Decision(
                verdict=Verdict.DENY,
                reason="Mediator unavailable",
                applied_rules=["client.mediator_unavailable"],
                grant=None,
            )
        try:
            return getattr(mediator, method)(request)
        except Exception as exc:
            return Decision(
                verdict=Verdict.DENY,
                reason=f"Mediator unavailable: {exc}",
                applied_rules=["client.mediator_error"],
                grant=None,
            )
