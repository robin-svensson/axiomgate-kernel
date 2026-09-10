"""P0 Cryptographic Approval Authorization Test Matrix (Tests 1–16)

Comprehensive adversarial verification of the Ed25519 asymmetric approval system,
replay protection, exact payload binding, and private-key isolation.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
import uuid
import pytest

from axiomgate_kernel.approval import (
    ApprovalSigner,
    ApprovalVerifier,
    generate_approval_keypair,
)

# Agaridentiteten ligger inte langre i paketet -- testerna far ange sin egen.
TRUSTED_OWNER_ID = "owner-under-test"

from axiomgate_kernel.config import (
    sanitize_agent_environment,
    get_approval_public_key,
    get_approval_private_key,
    set_approval_public_key,
    set_approval_private_key,
    ensure_approval_keys,
    _reset_context_for_testing,
)


@pytest.fixture(autouse=True)
def reset_config_state():
    _reset_context_for_testing()
    yield
    _reset_context_for_testing()


@pytest.fixture
def keypair():
    priv, pub = generate_approval_keypair()
    return priv, pub


@pytest.fixture
def signer_and_verifier(keypair):
    priv, pub = keypair
    signer = ApprovalSigner(priv)
    verifier = ApprovalVerifier(pub, trusted_owner_id=TRUSTED_OWNER_ID)
    return signer, verifier


def _valid_payload_dict(esc_id: str = "esc-test-001", tool: str = "terminal", args: dict = None, risk: str = "HIGH"):
    return {
        "escalation_id": esc_id,
        "tool": tool,
        "args": args if args is not None else {"command": "echo verified"},
        "risk": risk,
        "request_session_id": "session-test-001",
        "approver_id": TRUSTED_OWNER_ID,
        "decision": "APPROVE",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "nonce": uuid.uuid4().hex,
        "key_id": "ed25519-v1",
    }


# ---------------------------------------------------------------------------
# TEST 01: Positive Approval
# ---------------------------------------------------------------------------
def test_01_positive_approval(signer_and_verifier):
    """TEST 01: Valid Ed25519 signature from Owner permits execution."""
    signer, verifier = signer_and_verifier
    payload = _valid_payload_dict()
    envelope = signer.sign_approval(payload)

    result = verifier.consume(
        escalation_id=payload["escalation_id"],
        envelope=envelope,
        expected_tool=payload["tool"],
        expected_args=payload["args"],
        expected_risk=payload["risk"],
    )

    assert result.valid is True
    assert result.rule == "approval.ok"
    assert result.payload["decision"] == "APPROVE"


# ---------------------------------------------------------------------------
# TEST 02: Deny
# ---------------------------------------------------------------------------
def test_02_deny(signer_and_verifier):
    """TEST 02: Owner decision of DENY is rejected."""
    signer, verifier = signer_and_verifier
    payload = _valid_payload_dict()
    payload["decision"] = "DENY"
    envelope = signer.sign_approval(payload)

    result = verifier.consume(
        escalation_id=payload["escalation_id"],
        envelope=envelope,
        expected_tool=payload["tool"],
        expected_args=payload["args"],
        expected_risk=payload["risk"],
    )

    assert result.valid is False
    assert result.rule == "approval.decision_denied"


# ---------------------------------------------------------------------------
# TEST 03: Agent Forge Attempt
# ---------------------------------------------------------------------------
def test_03_agent_forge_attempt(signer_and_verifier):
    """TEST 03: Agent forging signature with random bytes or wrong key fails."""
    signer, verifier = signer_and_verifier
    payload = _valid_payload_dict()
    envelope = signer.sign_approval(payload)

    # Corrupt the signature
    envelope["signature"] = "00" * 64

    result = verifier.consume(
        escalation_id=payload["escalation_id"],
        envelope=envelope,
        expected_tool=payload["tool"],
        expected_args=payload["args"],
        expected_risk=payload["risk"],
    )

    assert result.valid is False
    assert result.rule == "approval.signature_verification_failed"


# ---------------------------------------------------------------------------
# TEST 04: Old SHA-256 Forge
# ---------------------------------------------------------------------------
def test_04_old_sha256_forge(signer_and_verifier):
    """TEST 04: Legacy unkeyed SHA-256 tokens and naked status=APPROVED are rejected."""
    _, verifier = signer_and_verifier
    payload = _valid_payload_dict()

    # Case A: SHA256 algorithm indicator
    sha256_envelope = {
        "status": "APPROVED",
        "algorithm": "SHA256",
        "payload": payload,
        "payload_hash": hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(),
    }
    res_a = verifier.verify(sha256_envelope)
    assert res_a.valid is False
    assert res_a.rule == "approval.legacy_sha256_rejected"

    # Case B: Naked status=APPROVED without signature
    naked_envelope = {
        "status": "APPROVED",
        "payload": payload,
    }
    res_b = verifier.verify(naked_envelope)
    assert res_b.valid is False
    assert res_b.rule == "approval.signature_missing"


# ---------------------------------------------------------------------------
# TEST 05: Tool Tamper
# ---------------------------------------------------------------------------
def test_05_tool_tamper(signer_and_verifier):
    """TEST 05: Approval for tool A presented for tool B is rejected."""
    signer, verifier = signer_and_verifier
    payload = _valid_payload_dict(tool="read_file")
    envelope = signer.sign_approval(payload)

    result = verifier.consume(
        escalation_id=payload["escalation_id"],
        envelope=envelope,
        expected_tool="terminal",  # Tampered
        expected_args=payload["args"],
        expected_risk=payload["risk"],
    )

    assert result.valid is False
    assert result.rule == "approval.tool_binding_mismatch"


# ---------------------------------------------------------------------------
# TEST 06: Args Tamper
# ---------------------------------------------------------------------------
def test_06_args_tamper(signer_and_verifier):
    """TEST 06: Modified arguments after approval signature are rejected."""
    signer, verifier = signer_and_verifier
    payload = _valid_payload_dict(args={"command": "ls /tmp"})
    envelope = signer.sign_approval(payload)

    result = verifier.consume(
        escalation_id=payload["escalation_id"],
        envelope=envelope,
        expected_tool=payload["tool"],
        expected_args={"command": "rm -rf /"},  # Malicious replacement
        expected_risk=payload["risk"],
    )

    assert result.valid is False
    assert result.rule == "approval.args_binding_mismatch"


# ---------------------------------------------------------------------------
# TEST 07: Risk Tamper
# ---------------------------------------------------------------------------
def test_07_risk_tamper(signer_and_verifier):
    """TEST 07: Approval for LOW risk cannot be used for HIGH risk execution."""
    signer, verifier = signer_and_verifier
    payload = _valid_payload_dict(risk="LOW")
    envelope = signer.sign_approval(payload)

    result = verifier.consume(
        escalation_id=payload["escalation_id"],
        envelope=envelope,
        expected_tool=payload["tool"],
        expected_args=payload["args"],
        expected_risk="HIGH",  # Escaped risk
    )

    assert result.valid is False
    assert result.rule == "approval.risk_binding_mismatch"


# ---------------------------------------------------------------------------
# TEST 08: Escalation ID Tamper
# ---------------------------------------------------------------------------
def test_08_escalation_id_tamper(signer_and_verifier):
    """TEST 08: Approval for escalation esc-1 presented for esc-2 is rejected."""
    signer, verifier = signer_and_verifier
    payload = _valid_payload_dict(esc_id="esc-001")
    envelope = signer.sign_approval(payload)

    result = verifier.consume(
        escalation_id="esc-002",  # Different escalation
        envelope=envelope,
        expected_tool=payload["tool"],
        expected_args=payload["args"],
        expected_risk=payload["risk"],
    )

    assert result.valid is False
    assert result.rule == "approval.escalation_binding_mismatch"


# ---------------------------------------------------------------------------
# TEST 09: Owner Identity Tamper
# ---------------------------------------------------------------------------
def test_09_owner_identity_tamper(signer_and_verifier):
    """TEST 09: Approval signed under a non-owner identity is rejected."""
    signer, verifier = signer_and_verifier
    payload = _valid_payload_dict()
    payload["approver_id"] = "9999999999"  # Impersonator
    envelope = signer.sign_approval(payload)

    result = verifier.consume(
        escalation_id=payload["escalation_id"],
        envelope=envelope,
        expected_tool=payload["tool"],
        expected_args=payload["args"],
        expected_risk=payload["risk"],
    )

    assert result.valid is False
    assert result.rule == "approval.unauthorized_approver"


# ---------------------------------------------------------------------------
# TEST 10: Cross-Escalation Signature Copy
# ---------------------------------------------------------------------------
def test_10_cross_escalation_signature_copy(signer_and_verifier):
    """TEST 10: Copying a signature from escalation A to escalation B payload fails."""
    signer, verifier = signer_and_verifier
    payload_a = _valid_payload_dict(esc_id="esc-A")
    envelope_a = signer.sign_approval(payload_a)

    payload_b = _valid_payload_dict(esc_id="esc-B")
    envelope_b = {
        "status": "APPROVED",
        "algorithm": "Ed25519",
        "key_id": "ed25519-v1",
        "payload": payload_b,
        "signature": envelope_a["signature"],  # Reused signature from A
    }

    result = verifier.consume(
        escalation_id="esc-B",
        envelope=envelope_b,
        expected_tool=payload_b["tool"],
        expected_args=payload_b["args"],
        expected_risk=payload_b["risk"],
    )

    assert result.valid is False
    assert result.rule == "approval.signature_verification_failed"


# ---------------------------------------------------------------------------
# TEST 11: Replay
# ---------------------------------------------------------------------------
def test_11_replay(signer_and_verifier):
    """TEST 11: Re-submitting an already consumed approval fails replay check."""
    signer, verifier = signer_and_verifier
    payload = _valid_payload_dict(esc_id="esc-replay-001")
    envelope = signer.sign_approval(payload)

    # First consumption succeeds
    r1 = verifier.consume(
        escalation_id="esc-replay-001",
        envelope=envelope,
        expected_tool=payload["tool"],
        expected_args=payload["args"],
        expected_risk=payload["risk"],
    )
    assert r1.valid is True

    # Replay attempt fails
    r2 = verifier.consume(
        escalation_id="esc-replay-001",
        envelope=envelope,
        expected_tool=payload["tool"],
        expected_args=payload["args"],
        expected_risk=payload["risk"],
    )
    assert r2.valid is False
    assert r2.rule in ("approval.already_consumed", "approval.nonce_replayed")


# ---------------------------------------------------------------------------
# TEST 12: Concurrent Consumption Exactly Once
# ---------------------------------------------------------------------------
def test_12_concurrent_consumption_exactly_once(signer_and_verifier):
    """TEST 12: Concurrent consumption race condition permits exactly one execution."""
    signer, verifier = signer_and_verifier
    payload = _valid_payload_dict(esc_id="esc-race-001")
    envelope = signer.sign_approval(payload)

    num_threads = 10
    results = []

    def _attempt_consume():
        return verifier.consume(
            escalation_id="esc-race-001",
            envelope=envelope,
            expected_tool=payload["tool"],
            expected_args=payload["args"],
            expected_risk=payload["risk"],
        )

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(_attempt_consume) for _ in range(num_threads)]
        for f in futures:
            results.append(f.result())

    successes = [r for r in results if r.valid is True]
    failures = [r for r in results if r.valid is False]

    assert len(successes) == 1, f"Expected exactly 1 success, got {len(successes)}"
    assert len(failures) == num_threads - 1


# ---------------------------------------------------------------------------
# TEST 13: Non-Owner Approval
# ---------------------------------------------------------------------------
def test_13_non_owner_approval(signer_and_verifier):
    """TEST 13: Approval signed by a rogue/non-owner Ed25519 keypair fails verification."""
    _, verifier = signer_and_verifier

    # Rogue keypair
    rogue_priv, _ = generate_approval_keypair()
    rogue_signer = ApprovalSigner(rogue_priv)

    payload = _valid_payload_dict()
    envelope = rogue_signer.sign_approval(payload)

    result = verifier.consume(
        escalation_id=payload["escalation_id"],
        envelope=envelope,
        expected_tool=payload["tool"],
        expected_args=payload["args"],
        expected_risk=payload["risk"],
    )

    assert result.valid is False
    assert result.rule == "approval.signature_verification_failed"


# ---------------------------------------------------------------------------
# TEST 14: Agent Cannot Read Private Key
# ---------------------------------------------------------------------------
def test_14_agent_cannot_read_private_key(keypair):
    """TEST 14: Verifier instance in agent context contains ONLY public key."""
    priv, pub = keypair
    verifier = ApprovalVerifier(pub, trusted_owner_id=TRUSTED_OWNER_ID)

    # Verifier does not have private key attribute
    assert not hasattr(verifier, "_private_key")
    assert not hasattr(verifier, "private_key")
    assert verifier.public_key_bytes == pub

    # Sanitize environment purges any signing keys from env AND process memory
    set_approval_private_key(priv)
    assert get_approval_private_key() is not None

    os.environ["AXIOMGATE_APPROVAL_PRIVATE_KEY"] = priv.hex()
    assert os.environ.get("AXIOMGATE_APPROVAL_PRIVATE_KEY") is not None
    sanitize_agent_environment()

    # Neither env nor memory nor config helper reveals private key
    assert os.environ.get("AXIOMGATE_APPROVAL_PRIVATE_KEY") is None
    assert os.environ.get("AXIOMGATE_APPROVAL_SIGNING_KEY") is None
    assert get_approval_private_key() is None

    # ensure_approval_keys() in agent context never generates or returns a private key
    priv_out, pub_out = ensure_approval_keys()
    assert priv_out is None
    assert get_approval_private_key() is None

    # Attempting to set private key in agent context is forbidden
    with pytest.raises(PermissionError):
        set_approval_private_key(priv)


# ---------------------------------------------------------------------------
# TEST 15: Private Key Absent From Repo / Queue / Logs
# ---------------------------------------------------------------------------
def test_15_private_key_absent_from_repo_queue_logs(signer_and_verifier, tmp_path):
    """TEST 15: Private key is never embedded in serialized payloads, queue items, or logs."""
    signer, verifier = signer_and_verifier
    payload = _valid_payload_dict()
    envelope = signer.sign_approval(payload)

    serialized = json.dumps(envelope)

    # The raw private key bytes or hex must NOT appear anywhere in the envelope
    priv_hex = signer._private_key.private_bytes_raw().hex()
    assert priv_hex not in serialized
    assert "private" not in serialized.lower()

    # Verify that payload only contains public/canonical fields
    assert set(envelope.keys()) == {"status", "algorithm", "key_id", "payload", "signature"}

    # Verify audit log integration does not log private key
    from axiomgate_kernel.audit import AuditLog
    from axiomgate_kernel.crypto import generate_key
    audit_path = str(tmp_path / "test_audit.log")
    audit = AuditLog(audit_path, generate_key())

    audit_verifier = ApprovalVerifier(signer.public_key_bytes, audit_log=audit,
                                     trusted_owner_id=TRUSTED_OWNER_ID)
    v_res = audit_verifier.consume(
        escalation_id=payload["escalation_id"],
        envelope=envelope,
        expected_tool=payload["tool"],
        expected_args=payload["args"],
        expected_risk=payload["risk"],
    )
    assert v_res.valid is True

    # Check audit log file
    with open(audit_path, "r", encoding="utf-8") as f:
        log_content = f.read()
    assert priv_hex not in log_content
    assert "approval_consumed" in log_content


# ---------------------------------------------------------------------------
# TEST 16: Full Regression Handshake
# ---------------------------------------------------------------------------
def test_16_full_regression_handshake(signer_and_verifier):
    """TEST 16: End-to-end multi-turn escalation and verified single-use execution."""
    signer, verifier = signer_and_verifier

    for i in range(5):
        esc_id = f"esc-multi-{i}"
        cmd = {"command": f"echo turn_{i}"}
        payload = _valid_payload_dict(esc_id=esc_id, args=cmd)
        envelope = signer.sign_approval(payload)

        # First consumption
        res = verifier.consume(
            escalation_id=esc_id,
            envelope=envelope,
            expected_tool="terminal",
            expected_args=cmd,
            expected_risk="HIGH",
        )
        assert res.valid is True

        # Second consumption fails
        res2 = verifier.consume(
            escalation_id=esc_id,
            envelope=envelope,
            expected_tool="terminal",
            expected_args=cmd,
            expected_risk="HIGH",
        )
        assert res2.valid is False


# ---------------------------------------------------------------------------
# TEST 17: Multiprocess Key Persistence and Process Isolation
# ---------------------------------------------------------------------------
def test_17_multiprocess_key_isolation_and_verification(tmp_path, monkeypatch):
    """TEST 17: Gateway persists public key to file; separate agent process loads public key only."""
    from axiomgate_kernel.config import (
        ensure_gateway_approval_keys,
        sanitize_agent_environment,
        get_approval_public_key,
        get_approval_private_key,
        _reset_context_for_testing,
    )
    monkeypatch.setenv("AXIOMGATE_KERNEL_HOME", str(tmp_path))

    # Phase 1: Gateway process boots up
    priv_gw, pub_gw = ensure_gateway_approval_keys()
    signer = ApprovalSigner(priv_gw)

    # Verify files created with correct permissions
    pub_file = tmp_path / "approval_ed25519.pub"
    priv_file = tmp_path / ".approval_ed25519.key"
    assert pub_file.exists()
    assert priv_file.exists()
    assert (priv_file.stat().st_mode & 0o777) == 0o600

    # Gateway signs an approval
    payload = _valid_payload_dict(esc_id="esc-proc-001")
    envelope = signer.sign_approval(payload)

    # Phase 2: Simulate separate Agent process
    _reset_context_for_testing()
    sanitize_agent_environment()

    # Agent cannot access private key
    assert get_approval_private_key() is None

    # Agent successfully loads public key from disk
    agent_pub = get_approval_public_key()
    assert agent_pub == pub_gw

    # Agent verifies and consumes approval
    agent_verifier = ApprovalVerifier(agent_pub, trusted_owner_id=TRUSTED_OWNER_ID)
    res = agent_verifier.consume(
        escalation_id="esc-proc-001",
        envelope=envelope,
        expected_tool=payload["tool"],
        expected_args=payload["args"],
        expected_risk=payload["risk"],
    )
    assert res.valid is True
    assert res.rule == "approval.ok"


# ---------------------------------------------------------------------------
# TEST 17: Nonce rullas tillbaka när audit-skrivningen faller
# ---------------------------------------------------------------------------
class _FallandeAudit:
    """AuditLog som faller en gång och lyckas därefter — ett övergående diskfel."""

    def __init__(self, antal_fel: int = 1):
        self.kvar = antal_fel
        self.lyckade = 0

    def append_approval_event(self, **kwargs):
        if self.kvar > 0:
            self.kvar -= 1
            raise OSError("disk full")
        self.lyckade += 1


def test_17_nonce_rullas_tillbaka_nar_audit_faller(keypair):
    """Nonce och escalation-id konsumeras före append_approval_event.

    Faller audit-skrivningen returnerar except-grenen valid=False med
    rule='approval.audit_failed' utan att backa konsumtionen. Nonce och
    escalation-id är då permanent brända: det legitima omförsöket avvisas
    som replay, och godkännandet kan aldrig genomföras.
    """
    priv, pub = keypair
    signer = ApprovalSigner(priv)
    audit = _FallandeAudit()
    verifier = ApprovalVerifier(
        pub,
        trusted_owner_id=TRUSTED_OWNER_ID,
        audit_log=audit,
    )
    payload = _valid_payload_dict(esc_id="esc-audit-rollback")
    envelope = signer.sign_approval(payload)

    forsta = verifier.consume(
        escalation_id=payload["escalation_id"],
        envelope=envelope,
        expected_tool=payload["tool"],
        expected_args=payload["args"],
        expected_risk=payload["risk"],
    )
    assert forsta.valid is False
    assert forsta.rule == "approval.audit_failed"

    andra = verifier.consume(
        escalation_id=payload["escalation_id"],
        envelope=envelope,
        expected_tool=payload["tool"],
        expected_args=payload["args"],
        expected_risk=payload["risk"],
    )
    assert andra.valid is True, (
        f"omförsöket avvisades med {andra.rule!r} — nonce och escalation-id "
        "brändes trots att godkännandet aldrig gick igenom"
    )
    assert audit.lyckade == 1
