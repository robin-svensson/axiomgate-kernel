"""AxiomGate Kernel — Grant Binding Property Tests

Tests for reserved grant binding security properties.
"""

import pytest
from datetime import datetime, timedelta, timezone

from axiomgate_kernel import (
    GrantError, ProvisioningToken, ReservedGrantStore, ReasonClass, make_capability,
    CapabilityRegistry, ActionType, RiskLevel, Role,
)
from axiomgate_kernel.grant import scope_hash


class TestGrantBinding:
    """Test grant binding properties."""

    def _store(self):
        return ReservedGrantStore(ttl=timedelta(hours=1))

    def test_create_pending(self):
        """Pending grant is created with correct fields."""
        s = self._store()
        s.create_pending_context(
            escalation_id="esc-1", principal_id="agent-a", agent_id="agent-a",
            request_id="req-1", action="EXECUTE", domain="code", risk_level="MEDIUM",
            payload_hash="hash-1", capability_id="cap-1", capability_scope_hash="scope-1",
            policy_version="v1", policy_hash="phash-1", provenance_kind="match",
            provenance_identity="repo|branch|head", reason_class=ReasonClass.OWNER_MANDATORY_ACTION,
        )
        grant = s.get_by_escalation("esc-1")
        assert grant is not None
        assert grant.principal_id == "agent-a"
        assert grant.action == "EXECUTE"
        assert grant.consumed is False

    def test_attach_owner_decision(self):
        """Owner decision is attached to grant."""
        s = self._store()
        s.create_pending_context(
            escalation_id="esc-1", principal_id="agent-a", agent_id="agent-a",
            request_id="req-1", action="EXECUTE", domain="code", risk_level="MEDIUM",
            payload_hash="hash-1", capability_id="cap-1", capability_scope_hash="scope-1",
            policy_version="v1", policy_hash="phash-1", provenance_kind="match",
            provenance_identity="repo|branch|head", reason_class=ReasonClass.OWNER_MANDATORY_ACTION,
        )
        s.attach_owner_decision("esc-1", "permit")
        grant = s.get_by_escalation("esc-1")
        assert grant.owner_decision == "permit"

    def test_consume_matching(self):
        """Consuming a matching grant succeeds."""
        s = self._store()
        s.create_pending_context(
            escalation_id="esc-1", principal_id="agent-a", agent_id="agent-a",
            request_id="req-1", action="EXECUTE", domain="code", risk_level="MEDIUM",
            payload_hash="hash-1", capability_id="cap-1", capability_scope_hash="scope-1",
            policy_version="v1", policy_hash="phash-1", provenance_kind="match",
            provenance_identity="repo|branch|head", reason_class=ReasonClass.OTHER,
        )
        s.attach_owner_decision("esc-1", "permit")
        consumed = s.consume_if_valid(
            "esc-1", principal_id="agent-a", agent_id="agent-a", request_id="req-1",
            action="EXECUTE", domain="code", risk_level="MEDIUM", payload_hash="hash-1",
            capability_id="cap-1", capability_scope_hash="scope-1", policy_hash="phash-1",
            provenance_identity="repo|branch|head",
        )
        assert consumed.consumed is True

    def test_consume_mismatch_denied(self):
        """Consuming a grant with wrong field is denied."""
        s = self._store()
        s.create_pending_context(
            escalation_id="esc-1", principal_id="agent-a", agent_id="agent-a",
            request_id="req-1", action="EXECUTE", domain="code", risk_level="MEDIUM",
            payload_hash="hash-1", capability_id="cap-1", capability_scope_hash="scope-1",
            policy_version="v1", policy_hash="phash-1", provenance_kind="match",
            provenance_identity="repo|branch|head", reason_class=ReasonClass.OTHER,
        )
        s.attach_owner_decision("esc-1", "permit")
        with pytest.raises(GrantError, match="binding mismatch"):
            s.consume_if_valid(
                "esc-1", principal_id="agent-b", agent_id="agent-a", request_id="req-1",  # wrong principal
                action="EXECUTE", domain="code", risk_level="MEDIUM", payload_hash="hash-1",
                capability_id="cap-1", capability_scope_hash="scope-1", policy_hash="phash-1",
                provenance_identity="repo|branch|head",
            )

    def test_consume_twice_denied(self):
        """Consuming a grant twice is denied."""
        s = self._store()
        s.create_pending_context(
            escalation_id="esc-1", principal_id="agent-a", agent_id="agent-a",
            request_id="req-1", action="EXECUTE", domain="code", risk_level="MEDIUM",
            payload_hash="hash-1", capability_id="cap-1", capability_scope_hash="scope-1",
            policy_version="v1", policy_hash="phash-1", provenance_kind="match",
            provenance_identity="repo|branch|head", reason_class=ReasonClass.OTHER,
        )
        s.attach_owner_decision("esc-1", "permit")
        s.consume_if_valid(
            "esc-1", principal_id="agent-a", agent_id="agent-a", request_id="req-1",
            action="EXECUTE", domain="code", risk_level="MEDIUM", payload_hash="hash-1",
            capability_id="cap-1", capability_scope_hash="scope-1", policy_hash="phash-1",
            provenance_identity="repo|branch|head",
        )
        with pytest.raises(GrantError, match="already consumed"):
            s.consume_if_valid(
                "esc-1", principal_id="agent-a", agent_id="agent-a", request_id="req-1",
                action="EXECUTE", domain="code", risk_level="MEDIUM", payload_hash="hash-1",
                capability_id="cap-1", capability_scope_hash="scope-1", policy_hash="phash-1",
                provenance_identity="repo|branch|head",
            )

    def test_scope_hash_stable(self):
        """Scope hash is deterministic for same capability."""
        cap = make_capability(
            capability_id="cap-1", principal_id="agent-a", role=Role.R_ENG,
            domains=["code"], action_types=[ActionType.EXECUTE],
            risk_ceiling=RiskLevel.MEDIUM, issued_by="Owner",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        h1 = scope_hash(cap)
        h2 = scope_hash(cap)
        assert h1 == h2

    def test_unconsume_rollback(self):
        """Unconsuming a consumed grant restores consumed=False atomically."""
        s = self._store()
        s.create_pending_context(
            escalation_id="esc-rollback", principal_id="agent-a", agent_id="agent-a",
            request_id="req-1", action="EXECUTE", domain="code", risk_level="MEDIUM",
            payload_hash="hash-1", capability_id="cap-1", capability_scope_hash="scope-1",
            policy_version="v1", policy_hash="phash-1", provenance_kind="match",
            provenance_identity="repo|branch|head", reason_class=ReasonClass.OTHER,
        )
        s.attach_owner_decision("esc-rollback", "permit")
        s.consume_if_valid(
            "esc-rollback", principal_id="agent-a", agent_id="agent-a", request_id="req-1",
            action="EXECUTE", domain="code", risk_level="MEDIUM", payload_hash="hash-1",
            capability_id="cap-1", capability_scope_hash="scope-1", policy_hash="phash-1",
            provenance_identity="repo|branch|head",
        )
        grant = s.get_by_escalation("esc-rollback")
        assert grant.consumed is True

        # Roll back consumption
        s.unconsume("esc-rollback")
        grant_restored = s.get_by_escalation("esc-rollback")
        assert grant_restored.consumed is False

        # Can now be consumed again
        reconsumed = s.consume_if_valid(
            "esc-rollback", principal_id="agent-a", agent_id="agent-a", request_id="req-1",
            action="EXECUTE", domain="code", risk_level="MEDIUM", payload_hash="hash-1",
            capability_id="cap-1", capability_scope_hash="scope-1", policy_hash="phash-1",
            provenance_identity="repo|branch|head",
        )
        assert reconsumed.consumed is True



class TestReasonClassSkips:
    """Vilka bindningar som slapps per reason class -- och vilka som inte gor det.

    Buggen: dokumentationen pastod att tva falt hoppas over vid POLICY och
    PROVENANCE. Koden hoppar tre -- aven capability_id och capability_scope --
    och det var varken kommenterat eller testat. Ett odokumenterat undantag i
    en sakerhetskontroll ar ett undantag ingen granskar.
    """

    def _store(self):
        return ReservedGrantStore(ttl=timedelta(hours=1))

    def _pending(self, store, reason_class):
        store.create_pending_context(
            escalation_id="esc-1", principal_id="agent-a", agent_id="agent-a",
            request_id="req-1", action="EXECUTE", domain="code", risk_level="MEDIUM",
            payload_hash="hash-1", capability_id="cap-1", capability_scope_hash="scope-1",
            policy_version="v1", policy_hash="phash-1", provenance_kind="match",
            provenance_identity="repo|branch|head", reason_class=reason_class,
        )
        store.attach_owner_decision("esc-1", "permit")

    def _consume(self, store, **overrides):
        args = dict(
            principal_id="agent-a", agent_id="agent-a", request_id="req-1",
            action="EXECUTE", domain="code", risk_level="MEDIUM",
            payload_hash="hash-1", capability_id="cap-1",
            capability_scope_hash="scope-1", policy_hash="phash-1",
            provenance_identity="repo|branch|head",
        )
        args.update(overrides)
        return store.consume_if_valid("esc-1", **args)

    @pytest.mark.parametrize("reason_class,field", [
        (ReasonClass.POLICY, "policy_hash"),
        (ReasonClass.PROVENANCE, "provenance_identity"),
        (ReasonClass.POLICY, "capability_id"),
        (ReasonClass.POLICY, "capability_scope_hash"),
        (ReasonClass.PROVENANCE, "capability_id"),
        (ReasonClass.PROVENANCE, "capability_scope_hash"),
    ])
    def test_skipped_field_does_not_block(self, reason_class, field):
        """De tre bindningar som slapps per klass hindrar inte inlosen."""
        s = self._store()
        self._pending(s, reason_class)
        assert self._consume(s, **{field: "changed"}).consumed is True

    @pytest.mark.parametrize("reason_class", [ReasonClass.POLICY, ReasonClass.PROVENANCE])
    @pytest.mark.parametrize("field", [
        "principal_id", "agent_id", "request_id", "action", "domain",
        "risk_level", "payload_hash",
    ])
    def test_remaining_bindings_still_hold(self, reason_class, field):
        """De atta som ar kvar binder fortfarande -- undantaget ar smalt."""
        s = self._store()
        self._pending(s, reason_class)
        with pytest.raises(GrantError, match="grant binding mismatch"):
            self._consume(s, **{field: "changed"})

    @pytest.mark.parametrize("field", [
        "policy_hash", "provenance_identity", "capability_id", "capability_scope_hash",
    ])
    def test_nothing_is_skipped_for_other_classes(self, field):
        """Utan policy-/provenansorsak binder alla elva."""
        s = self._store()
        self._pending(s, ReasonClass.OWNER_MANDATORY_ACTION)
        with pytest.raises(GrantError, match="grant binding mismatch"):
            self._consume(s, **{field: "changed"})
