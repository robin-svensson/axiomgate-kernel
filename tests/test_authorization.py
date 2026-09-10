"""AxiomGate Kernel — Authorization Property Tests

Tests for authorization security properties.
"""

import pytest
from datetime import datetime, timedelta, timezone

from axiomgate_kernel import (
    ActionType, RiskLevel, Role,
    make_capability, check_capability, CapabilityDecision,
)
from axiomgate_kernel.principal import Principal
from axiomgate_kernel.domain import OWNER_PRINCIPAL_ID, OWNER_MANDATORY_ACTIONS


class TestCapabilityCheck:
    """Test capability check logic properties."""

    def _make_cap(self, **kwargs):
        """Helper to create a capability with defaults."""
        defaults = dict(
            capability_id="cap-1",
            principal_id="agent-a",
            role=Role.R_ENG,
            domains=["code"],
            action_types=[ActionType.INSPECT, ActionType.PROPOSE, ActionType.EXECUTE],
            risk_ceiling=RiskLevel.MEDIUM,
            issued_by="Owner",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        defaults.update(kwargs)
        return make_capability(**defaults)

    def test_no_capability_denies(self):
        """No capability produces DENY."""
        principal = Principal("agent-a")
        check = check_capability(principal, None, ActionType.EXECUTE, "code", RiskLevel.MEDIUM)
        assert check.decision == CapabilityDecision.DENY
        assert "authz.no_capability" in check.rules

    def test_wrong_principal_denies(self):
        """Wrong principal produces DENY."""
        cap = self._make_cap(principal_id="agent-a")
        principal = Principal("agent-b")  # Different principal
        check = check_capability(principal, cap, ActionType.EXECUTE, "code", RiskLevel.MEDIUM)
        assert check.decision == CapabilityDecision.DENY
        assert "authz.principal_mismatch" in check.rules

    def test_wrong_domain_denies(self):
        """Wrong domain produces DENY."""
        cap = self._make_cap(domains=["code"])
        principal = Principal("agent-a")
        check = check_capability(principal, cap, ActionType.EXECUTE, "research", RiskLevel.MEDIUM)
        assert check.decision == CapabilityDecision.DENY
        assert "authz.domain_out_of_scope" in check.rules

    def test_wrong_action_denies(self):
        """Wrong action produces DENY."""
        cap = self._make_cap(action_types=[ActionType.EXECUTE])
        principal = Principal("agent-a")
        check = check_capability(principal, cap, ActionType.VERIFY, "code", RiskLevel.MEDIUM)
        assert check.decision == CapabilityDecision.DENY
        assert "authz.action_out_of_scope" in check.rules

    def test_risk_above_ceiling_denies(self):
        """Risk above ceiling produces DENY."""
        cap = self._make_cap(risk_ceiling=RiskLevel.LOW)
        principal = Principal("agent-a")
        check = check_capability(principal, cap, ActionType.EXECUTE, "code", RiskLevel.MEDIUM)
        assert check.decision == CapabilityDecision.DENY
        assert "authz.risk_ceiling" in check.rules

    def test_expired_denies(self):
        """Expired capability produces DENY."""
        cap = self._make_cap(
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
        )
        principal = Principal("agent-a")
        check = check_capability(principal, cap, ActionType.EXECUTE, "code", RiskLevel.MEDIUM)
        assert check.decision == CapabilityDecision.DENY
        assert "authz.expired" in check.rules

    def test_revoked_denies(self):
        """Revoked capability produces DENY."""
        cap = self._make_cap(revoked_at=datetime.now(timezone.utc))
        principal = Principal("agent-a")
        check = check_capability(principal, cap, ActionType.EXECUTE, "code", RiskLevel.MEDIUM)
        assert check.decision == CapabilityDecision.DENY
        assert "authz.revoked" in check.rules

    def test_valid_allows(self):
        """Valid capability within scope produces ALLOW."""
        cap = self._make_cap()
        principal = Principal("agent-a")
        check = check_capability(principal, cap, ActionType.EXECUTE, "code", RiskLevel.MEDIUM)
        assert check.decision == CapabilityDecision.ALLOW
        assert "authz.allow" in check.rules

    def test_owner_mandatory_commit(self):
        """COMMIT action for non-Owner produces OWNER_MANDATORY."""
        cap = self._make_cap()
        principal = Principal("agent-a")  # Non-owner
        check = check_capability(principal, cap, ActionType.COMMIT, "code", RiskLevel.MEDIUM)
        assert check.decision == CapabilityDecision.OWNER_MANDATORY
        assert "authz.owner_mandatory_action" in check.rules

    def test_owner_bypasses_escalation(self):
        """Owner principal bypasses owner-mandatory escalation."""
        cap = self._make_cap(
            principal_id=OWNER_PRINCIPAL_ID,
            role=Role.R_DEC,
            action_types=list(ActionType),
        )
        principal = Principal(OWNER_PRINCIPAL_ID)
        check = check_capability(principal, cap, ActionType.COMMIT, "code", RiskLevel.MEDIUM)
        assert check.decision == CapabilityDecision.ALLOW

    def test_self_authorization_impossible(self):
        """check_capability does not issue grants or execute actions."""
        cap = self._make_cap()
        principal = Principal("agent-a")
        check = check_capability(principal, cap, ActionType.EXECUTE, "code", RiskLevel.MEDIUM)
        # check_capability returns CapabilityCheck, not Decision
        # It has no grant field, no verdict field
        assert not hasattr(check, "grant")
        assert not hasattr(check, "verdict")
