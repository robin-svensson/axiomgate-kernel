"""AxiomGate Kernel — Test Configuration

Common fixtures for property-based and unit tests.
"""

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import pytest


from axiomgate_kernel import (
    ActionType,
    AuditLog,
    Authenticator,
    CapabilityRegistry,
    FixedProvenanceChecker,
    PolicySnapshot,
    PrincipalKeyStore,
    ProvisioningToken,
    RiskLevel,
    Role,
    generate_key,
    make_capability,
    sign_request,
)
from axiomgate_kernel.provenance import ProvenanceKind, ProvenanceResult


@pytest.fixture
def tmp_audit():
    """Create a temporary audit log."""
    tmpdir = tempfile.mkdtemp()
    audit_path = os.path.join(tmpdir, "audit.log")
    audit = AuditLog(audit_path, generate_key())
    yield audit
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture
def owner_key():
    """Generate an owner HMAC key."""
    return generate_key()


@pytest.fixture
def agent_key():
    """Generate an agent HMAC key."""
    return generate_key()


@pytest.fixture
def auth_system(owner_key, agent_key):
    """Create a complete authentication system with owner and agent."""
    token = ProvisioningToken()
    keys = PrincipalKeyStore()
    keys.register("owner", owner_key, token)
    keys.register("agent-a", agent_key, token)
    keys.seal(token)  # Same token for all operations
    return keys


@pytest.fixture
def registry_system():
    """Create a capability registry with owner and agent capabilities."""
    token = ProvisioningToken()
    registry = CapabilityRegistry()

    # Agent capability
    agent_cap = make_capability(
        capability_id="cap-a",
        principal_id="agent-a",
        role=Role.R_ENG,
        domains=["code", "research"],
        action_types=[ActionType.INSPECT, ActionType.PROPOSE, ActionType.EXECUTE],
        risk_ceiling=RiskLevel.MEDIUM,
        issued_by="Owner",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    registry.register(agent_cap, token)

    # Owner capability
    owner_cap = make_capability(
        capability_id="cap-owner",
        principal_id="owner",
        role=Role.R_DEC,
        domains=["code", "research", "governance"],
        action_types=list(ActionType),
        risk_ceiling=RiskLevel.HIGH,
        issued_by="Owner",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    registry.register(owner_cap, token)

    registry.seal(token)  # Same token for all operations
    return registry


@pytest.fixture
def fixed_provenance():
    """Create a fixed provenance checker that always returns MATCH."""
    return FixedProvenanceChecker(ProvenanceResult(ProvenanceKind.MATCH, "ok"))


@pytest.fixture
def default_policy():
    """Create a default valid policy."""
    return PolicySnapshot.from_body("v1", {"rules": ["default"]})


@pytest.fixture
def agent_signer(agent_key):
    """Create a function that signs requests for agent-a."""
    def signer(request_dict):
        from uuid import uuid4
        request_dict.setdefault("principal_id", "agent-a")
        request_dict.setdefault("agent_id", "agent-a")
        request_dict.setdefault("nonce", uuid4().hex)
        request_dict.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        request_dict.setdefault("request_id", f"req-{uuid4().hex[:8]}")
        return sign_request(request_dict, agent_key)
    return signer


@pytest.fixture
def owner_signer(owner_key):
    """Create a function that signs requests for owner."""
    def signer(request_dict):
        from uuid import uuid4
        request_dict.setdefault("principal_id", "owner")
        request_dict.setdefault("agent_id", "owner")
        request_dict.setdefault("nonce", uuid4().hex)
        request_dict.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        request_dict.setdefault("request_id", f"req-{uuid4().hex[:8]}")
        return sign_request(request_dict, owner_key)
    return signer
