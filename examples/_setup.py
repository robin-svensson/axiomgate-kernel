"""Shared bootstrap for the examples.

Builds a Mediator with one agent and one owner. Everything here is the real
public API — no test doubles except the provenance checker, which would
otherwise need a git repository.
"""

import os
import tempfile
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from axiomgate_kernel import (
    ActionType, AuditLog, Authenticator, CapabilityRegistry,
    FixedProvenanceChecker, Mediator, PolicySnapshot, PrincipalKeyStore,
    ProvisioningToken, RiskLevel, Role, generate_key, make_capability,
    sign_request,
)
from axiomgate_kernel.provenance import ProvenanceKind, ProvenanceResult


def build():
    """Return (mediator, agent_key, owner_key, audit, tmpdir)."""
    tmpdir = tempfile.mkdtemp(prefix="axiomgate-kernel-example-")

    # --- Identities. The token seals the store: after seal() no key can be
    # --- added or replaced, which is what makes the roster immutable.
    agent_key, owner_key = generate_key(), generate_key()
    token = ProvisioningToken()
    keys = PrincipalKeyStore()
    keys.register("agent-a", agent_key, token)
    keys.register("owner", owner_key, token)
    keys.seal(token)

    # --- Capabilities. The agent may INSPECT/PROPOSE/EXECUTE in the "code"
    # --- domain up to MEDIUM risk. Anything else is outside its grant.
    reg_token = ProvisioningToken()
    registry = CapabilityRegistry()
    now = datetime.now(timezone.utc)
    registry.register(make_capability(
        capability_id="cap-a", principal_id="agent-a", role=Role.R_ENG,
        domains=["code"],
        action_types=[ActionType.INSPECT, ActionType.PROPOSE, ActionType.EXECUTE],
        risk_ceiling=RiskLevel.MEDIUM, issued_by="Owner",
        issued_at=now, expires_at=now + timedelta(hours=1),
    ), reg_token)
    registry.register(make_capability(
        capability_id="cap-owner", principal_id="owner", role=Role.R_DEC,
        domains=["code"], action_types=list(ActionType),
        risk_ceiling=RiskLevel.HIGH, issued_by="Owner",
        issued_at=now, expires_at=now + timedelta(hours=1),
    ), reg_token)
    registry.seal(reg_token)

    audit = AuditLog(os.path.join(tmpdir, "audit.log"), generate_key())

    mediator = Mediator(
        authenticator=Authenticator(keys),
        registry=registry,
        audit=audit,
        provenance=FixedProvenanceChecker(ProvenanceResult(ProvenanceKind.MATCH, "ok")),
        policy=PolicySnapshot.from_body("v1", {"rules": ["default"]}),
    )
    return mediator, agent_key, owner_key, audit, tmpdir


def request(key, principal="agent-a", **fields):
    """Sign an action request as `principal`."""
    body = {
        "principal_id": principal,
        "agent_id": principal,
        "nonce": uuid4().hex,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": f"req-{uuid4().hex[:8]}",
    }
    body.update(fields)
    return sign_request(body, key)
