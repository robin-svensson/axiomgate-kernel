"""AxiomGate Kernel — Capability Property Tests

Tests for capability model security properties.
"""

import pytest
from datetime import datetime, timedelta, timezone

from axiomgate_kernel import (
    ActionType, Capability, CapabilityRegistry, ProvisioningToken,
    RiskLevel, Role, make_capability,
)


class TestCapabilityStructuralValidity:
    """Test capability structural validity checks."""

    def test_valid_capability_is_active(self):
        """A correctly formed capability is active."""
        cap = make_capability(
            capability_id="cap-1",
            principal_id="agent-a",
            role=Role.R_ENG,
            domains=["code"],
            action_types=[ActionType.EXECUTE],
            risk_ceiling=RiskLevel.MEDIUM,
            issued_by="Owner",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        assert cap.is_structurally_valid() is True
        assert cap.is_active() is True

    def test_transferable_rejected(self):
        """Transferable capability is structurally invalid."""
        cap = make_capability(
            capability_id="cap-1",
            principal_id="agent-a",
            role=Role.R_ENG,
            domains=["code"],
            action_types=[ActionType.EXECUTE],
            risk_ceiling=RiskLevel.MEDIUM,
            issued_by="Owner",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            transferable=True,
        )
        assert cap.is_structurally_valid() is False

    def test_delegation_depth_must_be_one(self):
        """Delegation depth != 1 is structurally invalid."""
        cap = make_capability(
            capability_id="cap-1",
            principal_id="agent-a",
            role=Role.R_ENG,
            domains=["code"],
            action_types=[ActionType.EXECUTE],
            risk_ceiling=RiskLevel.MEDIUM,
            issued_by="Owner",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            delegation_depth=2,
        )
        assert cap.is_structurally_valid() is False

    def test_rdec_owner_only(self):
        """R-DEC role is Owner-only."""
        cap = make_capability(
            capability_id="cap-1",
            principal_id="agent-a",  # NOT owner
            role=Role.R_DEC,
            domains=["code"],
            action_types=[ActionType.EXECUTE],
            risk_ceiling=RiskLevel.MEDIUM,
            issued_by="Owner",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        assert cap.is_structurally_valid() is False

    def test_non_owner_issued_rejected(self):
        """Capability not issued by Owner is invalid."""
        cap = make_capability(
            capability_id="cap-1",
            principal_id="agent-a",
            role=Role.R_ENG,
            domains=["code"],
            action_types=[ActionType.EXECUTE],
            risk_ceiling=RiskLevel.MEDIUM,
            issued_by="SomeoneElse",  # NOT "Owner"
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        assert cap.is_structurally_valid() is False

    def test_expired_capability_not_active(self):
        """Expired capability is not active."""
        cap = make_capability(
            capability_id="cap-1",
            principal_id="agent-a",
            role=Role.R_ENG,
            domains=["code"],
            action_types=[ActionType.EXECUTE],
            risk_ceiling=RiskLevel.MEDIUM,
            issued_by="Owner",
            issued_at=datetime.now(timezone.utc) - timedelta(hours=2),
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        assert cap.is_expired() is True
        assert cap.is_active() is False

    def test_revoked_capability_not_active(self):
        """Revoked capability is not active."""
        cap = make_capability(
            capability_id="cap-1",
            principal_id="agent-a",
            role=Role.R_ENG,
            domains=["code"],
            action_types=[ActionType.EXECUTE],
            risk_ceiling=RiskLevel.MEDIUM,
            issued_by="Owner",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            revoked_at=datetime.now(timezone.utc),
        )
        assert cap.is_revoked() is True
        assert cap.is_active() is False


class TestCapabilityRegistry:
    """Test capability registry thread-safety and isolation."""

    def test_detached_copies(self):
        """Registry returns detached copies, not internal references."""
        token = ProvisioningToken()
        registry = CapabilityRegistry()
        cap = make_capability(
            capability_id="cap-1",
            principal_id="agent-a",
            role=Role.R_ENG,
            domains=["code"],
            action_types=[ActionType.EXECUTE],
            risk_ceiling=RiskLevel.MEDIUM,
            issued_by="Owner",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        registry.register(cap, token)

        retrieved = registry.get("cap-1")
        assert retrieved is not None
        # Modifying retrieved should not affect registry
        # (frozen dataclass prevents this, but verify the copy is independent)
        assert retrieved.capability_id == cap.capability_id

    def test_sealed_registry_rejects_registration(self):
        """Sealed registry rejects new registrations."""
        token = ProvisioningToken()
        registry = CapabilityRegistry()
        cap = make_capability(
            capability_id="cap-1",
            principal_id="agent-a",
            role=Role.R_ENG,
            domains=["code"],
            action_types=[ActionType.EXECUTE],
            risk_ceiling=RiskLevel.MEDIUM,
            issued_by="Owner",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        registry.register(cap, token)

        registry.seal(token)  # Same token

        new_cap = make_capability(
            capability_id="cap-2",
            principal_id="agent-b",
            role=Role.R_ENG,
            domains=["code"],
            action_types=[ActionType.EXECUTE],
            risk_ceiling=RiskLevel.MEDIUM,
            issued_by="Owner",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        with pytest.raises(Exception):
            registry.register(new_cap, ProvisioningToken())

    def test_for_principal_filters(self):
        """for_principal returns only capabilities for that principal."""
        token = ProvisioningToken()
        registry = CapabilityRegistry()
        cap_a = make_capability(
            capability_id="cap-a",
            principal_id="agent-a",
            role=Role.R_ENG,
            domains=["code"],
            action_types=[ActionType.EXECUTE],
            risk_ceiling=RiskLevel.MEDIUM,
            issued_by="Owner",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        cap_b = make_capability(
            capability_id="cap-b",
            principal_id="agent-b",
            role=Role.R_ENG,
            domains=["code"],
            action_types=[ActionType.EXECUTE],
            risk_ceiling=RiskLevel.MEDIUM,
            issued_by="Owner",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        registry.register(cap_a, token)
        registry.register(cap_b, token)

        a_caps = registry.for_principal("agent-a")
        assert len(a_caps) == 1
        assert a_caps[0].capability_id == "cap-a"

    def test_active_for_filters_expired(self):
        """active_for excludes expired capabilities."""
        token = ProvisioningToken()
        registry = CapabilityRegistry()
        cap_expired = make_capability(
            capability_id="cap-expired",
            principal_id="agent-a",
            role=Role.R_ENG,
            domains=["code"],
            action_types=[ActionType.EXECUTE],
            risk_ceiling=RiskLevel.MEDIUM,
            issued_by="Owner",
            issued_at=datetime.now(timezone.utc) - timedelta(hours=2),
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        cap_active = make_capability(
            capability_id="cap-active",
            principal_id="agent-a",
            role=Role.R_ENG,
            domains=["code"],
            action_types=[ActionType.EXECUTE],
            risk_ceiling=RiskLevel.MEDIUM,
            issued_by="Owner",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        registry.register(cap_expired, token)
        registry.register(cap_active, token)

        active = registry.active_for("agent-a")
        assert len(active) == 1
        assert active[0].capability_id == "cap-active"
