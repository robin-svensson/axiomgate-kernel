"""AxiomGate Kernel — Mediator Integration Property Tests

Tests for the complete authorization pipeline.
"""

import pytest
import os
import tempfile
import shutil
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from axiomgate_kernel import (
    ActionType, AuditLog, Authenticator, CapabilityRegistry, FixedProvenanceChecker,
    Mediator, MediatorClient, PolicySnapshot, PrincipalKeyStore, ProvisioningToken,
    RiskLevel, Role, Verdict, generate_key, make_capability, sign_request,
)
from axiomgate_kernel.provenance import ProvenanceKind, ProvenanceResult


def _setup_mediator():
    """Create a complete mediator system for testing."""
    tmpdir = tempfile.mkdtemp()

    # Keys
    owner_key = generate_key()
    agent_key = generate_key()
    token = ProvisioningToken()
    keys = PrincipalKeyStore()
    keys.register("owner", owner_key, token)
    keys.register("agent-a", agent_key, token)
    keys.seal(token)  # Same token

    # Registry
    reg_token = ProvisioningToken()
    registry = CapabilityRegistry()
    agent_cap = make_capability(
        capability_id="cap-a", principal_id="agent-a", role=Role.R_ENG,
        domains=["code"], action_types=[ActionType.INSPECT, ActionType.PROPOSE, ActionType.EXECUTE],
        risk_ceiling=RiskLevel.MEDIUM, issued_by="Owner",
        issued_at=datetime.now(timezone.utc), expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    registry.register(agent_cap, reg_token)
    owner_cap = make_capability(
        capability_id="cap-owner", principal_id="owner", role=Role.R_DEC,
        domains=["code"], action_types=list(ActionType),
        risk_ceiling=RiskLevel.HIGH, issued_by="Owner",
        issued_at=datetime.now(timezone.utc), expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    registry.register(owner_cap, reg_token)
    registry.seal(reg_token)  # Same token

    # Audit
    audit = AuditLog(os.path.join(tmpdir, "audit.log"), generate_key())

    # Provenance
    provenance = FixedProvenanceChecker(ProvenanceResult(ProvenanceKind.MATCH, "ok"))

    # Policy
    policy = PolicySnapshot.from_body("v1", {"rules": ["default"]})

    # Mediator
    mediator = Mediator(
        authenticator=Authenticator(keys), registry=registry, audit=audit,
        provenance=provenance, policy=policy,
    )
    client = MediatorClient(mediator)

    return client, agent_key, owner_key, tmpdir


class TestMediatorPipeline:
    """Test the complete authorization pipeline."""

    def test_valid_request_permits(self):
        """Valid request within capability scope produces PERMIT."""
        client, owner_key, agent_key, tmpdir = self._setup()
        request = sign_request({
            "principal_id": "agent-a", "agent_id": "agent-a",
            "action_type": "EXECUTE", "domain": "code", "risk_level": "MEDIUM",
            "nonce": uuid4().hex, "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": "req-001",
        }, agent_key)
        decision = client.evaluate(request)
        assert decision.verdict == Verdict.PERMIT
        assert decision.grant is not None
        assert decision.audit_hash is not None
        shutil.rmtree(tmpdir)

    def test_owner_mandatory_escalates(self):
        """Owner-mandatory action produces ESCALATE."""
        client, owner_key, agent_key, tmpdir = self._setup()
        request = sign_request({
            "principal_id": "agent-a", "agent_id": "agent-a",
            "action_type": "COMMIT", "domain": "code", "risk_level": "MEDIUM",
            "nonce": uuid4().hex, "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": "req-002",
        }, agent_key)
        decision = client.evaluate(request)
        assert decision.verdict == Verdict.ESCALATE
        assert decision.escalation_id is not None
        shutil.rmtree(tmpdir)

    def test_invalid_mac_denies(self):
        """Invalid MAC produces DENY."""
        client, owner_key, agent_key, tmpdir = self._setup()
        request = {
            "principal_id": "agent-a", "agent_id": "agent-a",
            "action_type": "EXECUTE", "domain": "code", "risk_level": "MEDIUM",
            "nonce": uuid4().hex, "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": "req-003", "mac": "invalid",
        }
        decision = client.evaluate(request)
        assert decision.verdict == Verdict.DENY
        shutil.rmtree(tmpdir)

    def test_replay_denies(self):
        """Replayed request produces DENY."""
        client, owner_key, agent_key, tmpdir = self._setup()
        request = sign_request({
            "principal_id": "agent-a", "agent_id": "agent-a",
            "action_type": "EXECUTE", "domain": "code", "risk_level": "MEDIUM",
            "nonce": uuid4().hex, "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": "req-004",
        }, agent_key)
        decision1 = client.evaluate(request)
        assert decision1.verdict == Verdict.PERMIT
        decision2 = client.evaluate(request)  # Same request
        assert decision2.verdict == Verdict.DENY
        shutil.rmtree(tmpdir)

    def test_mediator_unavailable_denies(self):
        """Unavailable mediator produces DENY."""
        client = MediatorClient(None)
        decision = client.evaluate({"principal_id": "agent-a"})
        assert decision.verdict == Verdict.DENY
        assert "client.mediator_unavailable" in decision.applied_rules

    def test_mediator_never_executes(self):
        """Decision carries no execution flag; the mediator only decides.

        Producer/verifier separation is tested in
        test_evidence.py::test_producer_cannot_verify_own — not here.
        """
        client, owner_key, agent_key, tmpdir = self._setup()
        # The mediator should only return decisions, never execute
        request = sign_request({
            "principal_id": "agent-a", "agent_id": "agent-a",
            "action_type": "EXECUTE", "domain": "code", "risk_level": "MEDIUM",
            "nonce": uuid4().hex, "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": "req-005",
        }, agent_key)
        decision = client.evaluate(request)
        # Decision has verdict, grant, audit_hash - but no "executed" flag
        assert not hasattr(decision, "executed")
        assert not hasattr(decision, "action_performed")
        shutil.rmtree(tmpdir)

    def test_nan_float_request_fails_closed(self):
        """Malformed requests with NaN/Infinity return fail-closed DENY without crashing."""
        client, _, _, tmpdir = self._setup()
        decision = client.evaluate({"principal_id": "agent-a", "bad_float": float("nan")})
        assert decision.verdict == Verdict.DENY
        assert "canon.failed" in decision.applied_rules
        assert "canonicalization failed" in decision.reason
        shutil.rmtree(tmpdir)

    def test_unserializable_request_fails_closed(self):
        """Requests containing un-serializable objects return fail-closed DENY without crashing."""
        client, _, _, tmpdir = self._setup()
        decision = client.evaluate({"principal_id": "agent-a", "bad_obj": object()})
        assert decision.verdict == Verdict.DENY
        assert "canon.failed" in decision.applied_rules
        assert "canonicalization failed" in decision.reason
        shutil.rmtree(tmpdir)

    def test_non_mapping_request_fails_closed(self):
        """Non-mapping inputs return fail-closed DENY without crashing."""
        client, _, _, tmpdir = self._setup()
        decision = client.evaluate(["not", "a", "dict"])
        assert decision.verdict == Verdict.DENY
        assert "canon.failed" in decision.applied_rules
        shutil.rmtree(tmpdir)

    def _setup(self):
        """Helper to create mediator system."""
        tmpdir = tempfile.mkdtemp()

        owner_key = generate_key()
        agent_key = generate_key()
        token = ProvisioningToken()
        keys = PrincipalKeyStore()
        keys.register("owner", owner_key, token)
        keys.register("agent-a", agent_key, token)
        keys.seal(token)  # Same token

        reg_token = ProvisioningToken()
        registry = CapabilityRegistry()
        agent_cap = make_capability(
            capability_id="cap-a", principal_id="agent-a", role=Role.R_ENG,
            domains=["code"], action_types=[ActionType.INSPECT, ActionType.PROPOSE, ActionType.EXECUTE],
            risk_ceiling=RiskLevel.MEDIUM, issued_by="Owner",
            issued_at=datetime.now(timezone.utc), expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        registry.register(agent_cap, reg_token)
        owner_cap = make_capability(
            capability_id="cap-owner", principal_id="owner", role=Role.R_DEC,
            domains=["code"], action_types=list(ActionType),
            risk_ceiling=RiskLevel.HIGH, issued_by="Owner",
            issued_at=datetime.now(timezone.utc), expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        registry.register(owner_cap, reg_token)
        registry.seal(reg_token)  # Same token

        audit_path = os.path.join(tmpdir, "audit.log")
        audit = AuditLog(audit_path, generate_key())
        provenance = FixedProvenanceChecker(ProvenanceResult(ProvenanceKind.MATCH, "ok"))
        policy = PolicySnapshot.from_body("v1", {"rules": ["default"]})

        mediator = Mediator(
            authenticator=Authenticator(keys), registry=registry, audit=audit,
            provenance=provenance, policy=policy,
        )
        client = MediatorClient(mediator)

        return client, owner_key, agent_key, tmpdir
