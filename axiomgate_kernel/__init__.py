"""AxiomGate Kernel — AI-Agent Governance System

A modern, minimal, secure, auditable governance system for AI-agent activity.
"""

from .domain import (
    ActionType,
    EvidenceState,
    EscalationStatus,
    OWNER_MANDATORY_ACTIONS,
    OWNER_PRINCIPAL_ID,
    RiskLevel,
    Role,
    Verdict,
)
from .principal import Principal
from .crypto import generate_key, hmac_equal, hmac_sha256_hex, sha256_hex
from .canonical import canonical_bytes, canonical_json
from .canonical_request import CanonicalRequest, snapshot_request
from .decision import Decision
from .capability import Capability, CapabilityRegistry, make_capability
from .authentication import Authenticator, AuthnResult, NonceTracker, PrincipalKeyStore, sign_canonical, sign_request
from .authorization import CapabilityDecision, CapabilityCheck, check_capability
from .escalation import EscalationRecord, EscalationStore
from .grant import ReservedGrant, ReservedGrantStore, GrantError, ReasonClass, scope_hash
from .evidence import EvidenceRecord, EvidenceJournal, EvidenceError
from .provenance import ProvenanceChecker, ProvenanceResult, ProvenanceKind, FixedProvenanceChecker, GitProvenanceChecker
from .policy import PolicySnapshot
from .audit import AuditLog, AuditError
from .mediator import Mediator
from .client import MediatorClient
from .provisioning import ProvisioningToken, ProvisioningError
from .observation import (
    ObservationError, ObservationLog, ObservationRecord, check_invariants,
)
from .strict import NEW_LOG, StrictnessError, strict_audit_log, strict_mediator, strictness_report
from .serializers import (
    capability_to_persist, capability_from_persist,
    evidence_to_persist, evidence_from_persist,
    escalation_to_persist, escalation_from_persist,
    audit_record_to_persist,
)

__all__ = [
    # Types
    "ActionType", "RiskLevel", "Role", "Verdict",
    "EvidenceState", "EscalationStatus",
    "OWNER_PRINCIPAL_ID", "OWNER_MANDATORY_ACTIONS",
    # Identity
    "Principal",
    # Crypto
    "generate_key", "hmac_equal", "hmac_sha256_hex", "sha256_hex",
    # Canonical
    "canonical_bytes", "canonical_json",
    "CanonicalRequest", "snapshot_request",
    # Decision
    "Decision",
    # Capability
    "Capability", "CapabilityRegistry", "make_capability",
    # Authentication
    "Authenticator", "AuthnResult", "NonceTracker", "PrincipalKeyStore",
    "sign_canonical", "sign_request",
    # Authorization
    "CapabilityDecision", "CapabilityCheck", "check_capability",
    # Escalation
    "EscalationRecord", "EscalationStore",
    # Grant
    "ReservedGrant", "ReservedGrantStore", "GrantError", "ReasonClass", "scope_hash",
    # Evidence
    "EvidenceRecord", "EvidenceJournal", "EvidenceError",
    # Provenance
    "ProvenanceChecker", "ProvenanceResult", "ProvenanceKind", "FixedProvenanceChecker", "GitProvenanceChecker",
    # Policy
    "PolicySnapshot",
    # Audit
    "AuditLog", "AuditError",
    # Mediator
    "Mediator", "MediatorClient",
    # Strict wiring -- both opt-in protections at once, and a report of
    # which ones a live kernel actually has. See docs/ROADMAP.md.
    "NEW_LOG", "StrictnessError", "strict_audit_log", "strict_mediator",
    "strictness_report",
    "ObservationError", "ObservationLog", "ObservationRecord", "check_invariants",
]
