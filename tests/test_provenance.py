"""AxiomGate Kernel — Provenance Property Tests

Tests for provenance verification properties.
"""

import pytest
from axiomgate_kernel import FixedProvenanceChecker, ProvenanceResult, ProvenanceKind


class TestProvenanceChecks:
    """Test provenance check properties."""

    def test_match_produces_ok(self):
        """MATCH provenance produces ok=True."""
        p = FixedProvenanceChecker(ProvenanceResult(ProvenanceKind.MATCH, "ok"))
        result = p.check()
        assert result.ok is True
        assert result.kind == ProvenanceKind.MATCH

    def test_mismatch_not_ok(self):
        """MISMATCH provenance produces ok=False."""
        p = FixedProvenanceChecker(ProvenanceResult(ProvenanceKind.MISMATCH, "mismatch"))
        result = p.check()
        assert result.ok is False
        assert result.kind == ProvenanceKind.MISMATCH

    def test_unavailable_not_ok(self):
        """UNAVAILABLE provenance produces ok=False."""
        p = FixedProvenanceChecker(ProvenanceResult(ProvenanceKind.UNAVAILABLE, "unavailable"))
        result = p.check()
        assert result.ok is False
        assert result.kind == ProvenanceKind.UNAVAILABLE

    def test_provenance_identity_stable(self):
        """Provenance identity is stable for same values."""
        result = ProvenanceResult(ProvenanceKind.MATCH, "ok", "repo", "branch", "head123")
        assert result.identity == "repo|branch|head123"
