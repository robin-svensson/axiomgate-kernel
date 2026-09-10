"""AxiomGate Kernel — Policy Integrity Property Tests

Tests for policy integrity properties.
"""

import pytest
from axiomgate_kernel import PolicySnapshot


class TestPolicyIntegrity:
    """Test policy integrity checks."""

    def test_valid_policy_permits(self):
        """Valid policy with correct hash does not block PERMIT."""
        p = PolicySnapshot.from_body("v1", {"rules": ["default"]})
        assert p.blocks_permit() is False

    def test_modified_body_blocks(self):
        """Modified body produces hash mismatch and blocks PERMIT."""
        p = PolicySnapshot.from_body("v1", {"rules": ["default"]})
        # Create a new policy with different body but same version
        p2 = PolicySnapshot(version="v1", body={"rules": ["modified"]}, hash=p.hash)
        assert p2.blocks_permit() is True

    def test_empty_hash_blocks(self):
        """Empty hash blocks PERMIT."""
        p = PolicySnapshot(version="v1", body={"rules": ["default"]}, hash="")
        assert p.blocks_permit() is True

    def test_placeholder_blocks(self):
        """Placeholder policy blocks PERMIT."""
        p = PolicySnapshot.placeholder()
        assert p.blocks_permit() is True
        assert p.is_placeholder() is True

    def test_corrupt_blocks(self):
        """Corrupt policy blocks PERMIT."""
        p = PolicySnapshot.corrupt()
        assert p.blocks_permit() is True
        assert p.readable is False

    def test_policy_identity_stable(self):
        """Policy identity is stable for same version+hash."""
        p = PolicySnapshot.from_body("v1", {"rules": ["default"]})
        assert p.identity() == f"v1:{p.hash}"

    def test_policy_immutable(self):
        """Policy body is immutable (MappingProxyType)."""
        p = PolicySnapshot.from_body("v1", {"rules": ["default"]})
        from types import MappingProxyType
        assert isinstance(p.body, MappingProxyType)
