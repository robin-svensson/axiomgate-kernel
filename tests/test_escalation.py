"""AxiomGate Kernel — Escalation Property Tests

Tests for escalation state machine properties.
"""

import pytest
from axiomgate_kernel import EscalationStore, EscalationStatus
from axiomgate_kernel.escalation import EscalationError


class TestEscalationStateMachine:
    """Test escalation state machine transitions."""

    def _store(self):
        return EscalationStore()

    def test_creates_pending(self):
        """Escalation starts PENDING."""
        s = self._store()
        record = s.create("esc-1", "req-1", "agent-a", "hash-1", "reason", "owner_mandatory_action")
        assert record.status is EscalationStatus.PENDING

    def test_decide_transitions_to_decided(self):
        """Valid Owner decision transitions to DECIDED."""
        s = self._store()
        s.create("esc-1", "req-1", "agent-a", "hash-1", "reason", "owner_mandatory_action")
        record = s.mediator_decide("esc-1", "permit", "owner")
        assert record.status is EscalationStatus.DECIDED
        assert record.owner_decision == "permit"
        assert record.owner_principal == "owner"

    def test_invalid_decision_rejected(self):
        """Invalid decision string is rejected."""
        s = self._store()
        s.create("esc-1", "req-1", "agent-a", "hash-1", "reason", "owner_mandatory_action")
        with pytest.raises(EscalationError, match="invalid owner decision"):
            s.mediator_decide("esc-1", "invalid", "owner")

    def test_decide_pending_only(self):
        """Only PENDING escalations can be decided."""
        s = self._store()
        s.create("esc-1", "req-1", "agent-a", "hash-1", "reason", "owner_mandatory_action")
        s.mediator_decide("esc-1", "permit", "owner")
        with pytest.raises(EscalationError, match="not pending"):
            s.mediator_decide("esc-1", "deny", "owner")

    def test_resolve_after_decide(self):
        """Resolution requires DECIDED state."""
        s = self._store()
        s.create("esc-1", "req-1", "agent-a", "hash-1", "reason", "owner_mandatory_action")
        with pytest.raises(EscalationError, match="cannot resolve before decide"):
            s.mediator_resolve("esc-1")

    def test_resolve_transitions_to_resolved(self):
        """Resolution transitions to RESOLVED."""
        s = self._store()
        s.create("esc-1", "req-1", "agent-a", "hash-1", "reason", "owner_mandatory_action")
        s.mediator_decide("esc-1", "permit", "owner")
        record = s.mediator_resolve("esc-1")
        assert record.status is EscalationStatus.RESOLVED

    def test_cannot_resolve_twice(self):
        """Cannot resolve an already resolved escalation."""
        s = self._store()
        s.create("esc-1", "req-1", "agent-a", "hash-1", "reason", "owner_mandatory_action")
        s.mediator_decide("esc-1", "permit", "owner")
        s.mediator_resolve("esc-1")
        with pytest.raises(EscalationError, match="not decided"):
            s.mediator_resolve("esc-1")

    def test_duplicate_escalation_rejected(self):
        """Duplicate escalation ID is rejected."""
        s = self._store()
        s.create("esc-1", "req-1", "agent-a", "hash-1", "reason", "owner_mandatory_action")
        with pytest.raises(EscalationError, match="escalation exists"):
            s.create("esc-1", "req-2", "agent-b", "hash-2", "reason2", "other")

    def test_not_found_rejected(self):
        """Non-existent escalation is rejected."""
        s = self._store()
        with pytest.raises(EscalationError, match="not found"):
            s.mediator_decide("esc-nonexistent", "permit", "owner")
