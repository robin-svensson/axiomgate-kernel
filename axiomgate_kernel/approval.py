"""AxiomGate Kernel — Asymmetric Cryptographic Approval System (Ed25519)

Provides non-forgeable, cryptographically bound approval tokens signed by the
Owner out of band using Ed25519 digital signatures. The kernel never
learns which channel the Owner approved through -- only that the signature
verifies against the configured public key and names the trusted owner id.
Verifier in agent runtime holds ONLY the public key.

Security Invariants:
1. Non-forgeability: Cannot be forged without the 32-byte Ed25519 private key.
2. Exact Binding: Strictly binds escalation_id, tool, args, risk, session_id,
   approver_id, decision, timestamp, nonce, and key_id.
3. Anti-Replay: Nonce consumption tracking + strict timestamp TTL window.
4. Single-Use: Thread-safe atomic consumption prevents double-execution.
5. Legacy Rejection: Unkeyed SHA-256 digests and naked 'status=APPROVED' are rejected fail-closed.
"""

from __future__ import annotations

import collections
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
import os
import threading
from typing import Any, Dict, Optional, Set, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from .redaction import get_redacting_logger
from .canonical import canonical_bytes, canonical_json

logger = get_redacting_logger(__name__)

DEFAULT_KEY_ID = "ed25519-v1"
# No built-in owner. A hardcoded default made a stranger's identity the
# sole trusted approver in every installation that did not configure one --
# fail-open toward an outsider, in the one control that decides approval.
# Absence of an owner is absence, not a value that may be substituted.
DEFAULT_MAX_TTL_SECONDS = 300


class ApprovalError(Exception):
    """Base exception for approval authorization failures."""
    pass


class ApprovalForgedError(ApprovalError):
    """Raised when an approval token signature is forged or invalid."""
    pass


class ApprovalTamperedError(ApprovalError):
    """Raised when approval parameters do not match requested execution."""
    pass


class ApprovalReplayError(ApprovalError):
    """Raised when an approval token is replayed or re-consumed."""
    pass


@dataclass(frozen=True)
class ApprovalPayload:
    """Canonical approval payload data binding."""
    escalation_id: str
    tool: str
    args: Dict[str, Any]
    risk: str
    request_session_id: str
    approver_id: str
    decision: str
    timestamp: str
    nonce: str
    key_id: str = DEFAULT_KEY_ID

    def as_dict(self) -> Dict[str, Any]:
        return {
            "escalation_id": self.escalation_id,
            "tool": self.tool,
            "args": self.args,
            "risk": self.risk,
            "request_session_id": self.request_session_id,
            "approver_id": self.approver_id,
            "decision": self.decision,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "key_id": self.key_id,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.as_dict())


@dataclass(frozen=True)
class ApprovalVerificationResult:
    """Outcome of cryptographic approval verification."""
    valid: bool
    reason: str
    rule: str
    payload: Optional[Dict[str, Any]] = None
    envelope: Optional[Dict[str, Any]] = None


def generate_approval_keypair() -> Tuple[bytes, bytes]:
    """Generate a new 32-byte Ed25519 keypair (private_bytes, public_bytes)."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv.private_bytes_raw(), pub.public_bytes_raw()


class ApprovalSigner:
    """Owner-authenticated Gateway approval signer.

    Holds the private signing key. MUST NOT be instantiated in agent context.
    """

    def __init__(self, private_key_bytes: bytes, key_id: str = DEFAULT_KEY_ID) -> None:
        if not private_key_bytes or len(private_key_bytes) != 32:
            raise ValueError("Ed25519 private key must be exactly 32 bytes")
        self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        self._public_key_bytes = self._private_key.public_key().public_bytes_raw()
        self._key_id = key_id

    @property
    def public_key_bytes(self) -> bytes:
        """Get corresponding public key bytes for verifier registration."""
        return self._public_key_bytes

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign_approval(self, payload_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Cryptographically sign an approval payload with Ed25519.

        Returns the signed approval envelope.
        """
        required_fields = {
            "escalation_id", "tool", "args", "risk",
            "request_session_id", "approver_id",
            "decision", "timestamp", "nonce",
        }
        missing = required_fields - set(payload_dict.keys())
        if missing:
            raise ValueError(f"Missing required fields for approval payload: {missing}")

        payload = {
            "escalation_id": str(payload_dict["escalation_id"]),
            "tool": str(payload_dict["tool"]),
            "args": dict(payload_dict["args"]) if isinstance(payload_dict["args"], dict) else {},
            "risk": str(payload_dict["risk"]),
            "request_session_id": str(payload_dict["request_session_id"]),
            "approver_id": str(payload_dict["approver_id"]),
            "decision": str(payload_dict["decision"]).upper(),
            "timestamp": str(payload_dict["timestamp"]),
            "nonce": str(payload_dict["nonce"]),
            "key_id": str(payload_dict.get("key_id", self._key_id)),
        }

        # Canonical encoding of the payload
        msg_bytes = canonical_bytes(payload)
        sig_bytes = self._private_key.sign(msg_bytes)

        return {
            "status": "APPROVED" if payload["decision"] == "APPROVE" else "DENIED",
            "algorithm": "Ed25519",
            "key_id": payload["key_id"],
            "payload": payload,
            "signature": sig_bytes.hex(),
        }


class ApprovalVerifier:
    """Agent runtime approval verifier.

    Possesses ONLY the public key. Cannot sign or forge approvals.
    Enforces replay protection and single-use atomic consumption.
    """

    def __init__(
        self,
        public_key_bytes: bytes,
        trusted_owner_id: Optional[str] = None,
        max_ttl_seconds: int = DEFAULT_MAX_TTL_SECONDS,
        key_id: str = DEFAULT_KEY_ID,
        audit_log: Optional[Any] = None,
    ) -> None:
        if not public_key_bytes or len(public_key_bytes) != 32:
            raise ValueError("Ed25519 public key must be exactly 32 bytes")
        self._public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        self._public_key_bytes = public_key_bytes
        owner = trusted_owner_id or os.environ.get("AXIOMGATE_OWNER_ID") or ""
        owner = str(owner).strip()
        if not owner:
            raise ValueError(
                "no trusted owner configured: pass trusted_owner_id or set "
                "AXIOMGATE_OWNER_ID. Refusing to substitute a default."
            )
        self._trusted_owner_id = owner
        self._max_ttl = timedelta(seconds=max_ttl_seconds)
        self._key_id = key_id
        self._audit_log = audit_log

        # State tracking for replay and single-use
        self._consumed_nonces: collections.OrderedDict[str, datetime] = collections.OrderedDict()
        self._consumed_escalations: Set[str] = set()
        self._lock = threading.Lock()

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key_bytes

    @property
    def key_id(self) -> str:
        return self._key_id

    def verify(
        self,
        envelope: Dict[str, Any],
        expected_tool: Optional[str] = None,
        expected_args: Optional[Dict[str, Any]] = None,
        expected_escalation_id: Optional[str] = None,
        expected_risk: Optional[str] = None,
        expected_session_id: Optional[str] = None,
    ) -> ApprovalVerificationResult:
        """Verify an approval envelope against constraints without consuming it."""
        return self._verify_internal(
            envelope=envelope,
            expected_tool=expected_tool,
            expected_args=expected_args,
            expected_escalation_id=expected_escalation_id,
            expected_risk=expected_risk,
            expected_session_id=expected_session_id,
            consume=False,
        )

    def consume(
        self,
        escalation_id: str,
        envelope: Dict[str, Any],
        expected_tool: str,
        expected_args: Dict[str, Any],
        expected_risk: str,
        expected_session_id: Optional[str] = None,
    ) -> ApprovalVerificationResult:
        """Atomically verify and consume an approval token for single-use execution."""
        return self._verify_internal(
            envelope=envelope,
            expected_tool=expected_tool,
            expected_args=expected_args,
            expected_escalation_id=escalation_id,
            expected_risk=expected_risk,
            expected_session_id=expected_session_id,
            consume=True,
        )

    def _verify_internal(
        self,
        envelope: Dict[str, Any],
        expected_tool: Optional[str],
        expected_args: Optional[Dict[str, Any]],
        expected_escalation_id: Optional[str],
        expected_risk: Optional[str],
        expected_session_id: Optional[str],
        consume: bool,
    ) -> ApprovalVerificationResult:
        """Internal verification logic with optional atomic consumption."""
        if not isinstance(envelope, dict):
            return ApprovalVerificationResult(
                valid=False,
                reason="Approval envelope must be a dictionary",
                rule="approval.invalid_envelope",
            )

        # 1. Reject legacy SHA-256 and unkeyed digests
        algo = envelope.get("algorithm", "")
        if algo in ("SHA256", "sha256") or ("payload_hash" in envelope and "signature" not in envelope):
            return ApprovalVerificationResult(
                valid=False,
                reason="Legacy SHA-256 approval format rejected: cryptographic asymmetric signature required",
                rule="approval.legacy_sha256_rejected",
            )

        # 2. Reject naked status without signature
        signature_hex = envelope.get("signature")
        if not signature_hex or not isinstance(signature_hex, str):
            return ApprovalVerificationResult(
                valid=False,
                reason="Cryptographic approval signature missing (status=APPROVED alone is insufficient)",
                rule="approval.signature_missing",
            )

        if algo != "Ed25519":
            return ApprovalVerificationResult(
                valid=False,
                reason=f"Unsupported algorithm '{algo}': Ed25519 required",
                rule="approval.unsupported_algorithm",
            )

        try:
            sig_bytes = bytes.fromhex(signature_hex)
            if len(sig_bytes) != 64:
                return ApprovalVerificationResult(
                    valid=False,
                    reason="Invalid signature length: Ed25519 signature must be 64 bytes",
                    rule="approval.invalid_signature_length",
                )
        except ValueError:
            return ApprovalVerificationResult(
                valid=False,
                reason="Invalid signature encoding: must be hex",
                rule="approval.invalid_signature_encoding",
            )

        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            return ApprovalVerificationResult(
                valid=False,
                reason="Approval payload missing or invalid",
                rule="approval.payload_missing",
            )

        # 3. Verify payload decision is APPROVE
        decision = str(payload.get("decision", "")).upper()
        if decision != "APPROVE":
            return ApprovalVerificationResult(
                valid=False,
                reason=f"Approval decision is not APPROVE (got '{decision}')",
                rule="approval.decision_denied",
                payload=payload,
            )

        # 4. Verify Owner identity
        approver_id = str(payload.get("approver_id", ""))
        if approver_id != self._trusted_owner_id:
            return ApprovalVerificationResult(
                valid=False,
                reason=f"Approver identity mismatch: '{approver_id}' is not trusted Owner '{self._trusted_owner_id}'",
                rule="approval.unauthorized_approver",
                payload=payload,
            )

        # 5. Verify escalation_id binding
        payload_esc_id = str(payload.get("escalation_id", ""))
        if not payload_esc_id:
            return ApprovalVerificationResult(
                valid=False,
                reason="Escalation ID missing in approval payload",
                rule="approval.missing_escalation_id",
                payload=payload,
            )
        if expected_escalation_id and payload_esc_id != expected_escalation_id:
            return ApprovalVerificationResult(
                valid=False,
                reason=f"Escalation ID binding mismatch: token is for '{payload_esc_id}', expected '{expected_escalation_id}'",
                rule="approval.escalation_binding_mismatch",
                payload=payload,
            )

        # 6. Verify tool binding
        payload_tool = str(payload.get("tool", ""))
        if expected_tool and payload_tool != expected_tool:
            return ApprovalVerificationResult(
                valid=False,
                reason=f"Tool binding mismatch: token is for '{payload_tool}', expected '{expected_tool}'",
                rule="approval.tool_binding_mismatch",
                payload=payload,
            )

        # 7. Verify args binding
        payload_args = payload.get("args")
        if not isinstance(payload_args, dict):
            return ApprovalVerificationResult(
                valid=False,
                reason="Tool args missing or invalid in approval payload",
                rule="approval.invalid_payload_args",
                payload=payload,
            )
        if expected_args is not None:
            try:
                if canonical_bytes(payload_args) != canonical_bytes(expected_args):
                    return ApprovalVerificationResult(
                        valid=False,
                        reason="Tool args binding mismatch: arguments altered after approval",
                        rule="approval.args_binding_mismatch",
                        payload=payload,
                    )
            except Exception:
                return ApprovalVerificationResult(
                    valid=False,
                    reason="Tool args serialization failed during canonical verification",
                    rule="approval.args_encoding_error",
                    payload=payload,
                )

        # 8. Verify risk binding
        payload_risk = str(payload.get("risk", ""))
        if expected_risk and payload_risk != expected_risk:
            return ApprovalVerificationResult(
                valid=False,
                reason=f"Risk binding mismatch: token is for '{payload_risk}', expected '{expected_risk}'",
                rule="approval.risk_binding_mismatch",
                payload=payload,
            )

        # 9. Verify session binding if specified
        payload_session = str(payload.get("request_session_id", ""))
        if expected_session_id and payload_session != expected_session_id:
            return ApprovalVerificationResult(
                valid=False,
                reason=f"Session binding mismatch: token is for '{payload_session}', expected '{expected_session_id}'",
                rule="approval.session_binding_mismatch",
                payload=payload,
            )

        # 10. Freshness & Strict TTL
        ts_str = payload.get("timestamp")
        if not ts_str or not isinstance(ts_str, str):
            return ApprovalVerificationResult(
                valid=False,
                reason="Timestamp missing in approval payload",
                rule="approval.timestamp_missing",
                payload=payload,
            )
        try:
            ts = datetime.fromisoformat(ts_str)
            if ts.tzinfo is None:
                return ApprovalVerificationResult(
                    valid=False,
                    reason="Naive timestamp rejected: must be timezone-aware UTC",
                    rule="approval.naive_timestamp",
                    payload=payload,
                )
        except ValueError:
            return ApprovalVerificationResult(
                valid=False,
                reason="Invalid ISO8601 timestamp in approval payload",
                rule="approval.malformed_timestamp",
                payload=payload,
            )

        now = datetime.now(timezone.utc)
        if now - ts > self._max_ttl:
            return ApprovalVerificationResult(
                valid=False,
                reason=f"Approval expired: issued {ts_str}, maximum TTL {self._max_ttl.total_seconds()}s exceeded",
                rule="approval.expired",
                payload=payload,
            )
        if ts > now + timedelta(seconds=5):
            return ApprovalVerificationResult(
                valid=False,
                reason=f"Future-dated approval rejected: timestamp {ts_str} is in the future",
                rule="approval.future_timestamp",
                payload=payload,
            )

        # 11. Nonce presence
        nonce = str(payload.get("nonce", "")).strip()
        if not nonce:
            return ApprovalVerificationResult(
                valid=False,
                reason="Nonce missing in approval payload",
                rule="approval.nonce_missing",
                payload=payload,
            )

        # 12. Cryptographic Signature Verification
        msg_bytes = canonical_bytes(payload)
        try:
            self._public_key.verify(sig_bytes, msg_bytes)
        except InvalidSignature:
            return ApprovalVerificationResult(
                valid=False,
                reason="Cryptographic signature verification failed: invalid Ed25519 signature",
                rule="approval.signature_verification_failed",
                payload=payload,
            )
        except Exception as exc:
            return ApprovalVerificationResult(
                valid=False,
                reason=f"Cryptographic verification error: {exc}",
                rule="approval.verification_error",
                payload=payload,
            )

        # 13. Replay Protection and Atomic Single-Use Consumption
        with self._lock:
            # Check if escalation already consumed
            if payload_esc_id in self._consumed_escalations:
                return ApprovalVerificationResult(
                    valid=False,
                    reason=f"Escalation '{payload_esc_id}' has already been consumed (single-use)",
                    rule="approval.already_consumed",
                    payload=payload,
                )

            # Check if nonce already seen
            if nonce in self._consumed_nonces:
                return ApprovalVerificationResult(
                    valid=False,
                    reason=f"Nonce '{nonce}' has already been consumed (replay attempt)",
                    rule="approval.nonce_replayed",
                    payload=payload,
                )

            if consume:
                # Evict expired nonces to maintain bounded memory
                cutoff = now - self._max_ttl
                while self._consumed_nonces:
                    first_nonce, first_ts = next(iter(self._consumed_nonces.items()))
                    if first_ts < cutoff:
                        self._consumed_nonces.popitem(last=False)
                    else:
                        break

                self._consumed_nonces[nonce] = ts
                self._consumed_escalations.add(payload_esc_id)

                # Record consumption in audit log if configured
                if self._audit_log is not None:
                    try:
                        self._audit_log.append_approval_event(
                            event_type="approval_consumed",
                            escalation_id=payload_esc_id,
                            tool=payload_tool,
                            decision=decision,
                            approver=approver_id,
                            signature_prefix=sig_bytes[:8].hex(),
                            details={"rule": "approval.ok", "key_id": self._key_id},
                        )
                    except Exception as _aud_err:
                        logger.error("Approval audit logging error: %s", _aud_err)
                        # Roll back the consumption. The approval never went
                        # through, so the nonce and escalation id must not stay
                        # burned -- otherwise the legitimate retry is rejected
                        # as a replay and the action can never be carried out.
                        self._consumed_nonces.pop(nonce, None)
                        self._consumed_escalations.discard(payload_esc_id)
                        return ApprovalVerificationResult(
                            valid=False,
                            reason=f"Audit recording failed: {_aud_err}",
                            rule="approval.audit_failed",
                        )

        return ApprovalVerificationResult(
            valid=True,
            reason="Cryptographic authorization verified (Ed25519)",
            rule="approval.ok",
            payload=payload,
            envelope=envelope,
        )
