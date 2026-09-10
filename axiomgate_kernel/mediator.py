"""AxiomGate Kernel — Mediator

Sole authorization chokepoint. Does not execute actions.
"""

from datetime import datetime, timezone
from typing import List, Optional, Tuple
from uuid import uuid4

from .audit import AuditLog
from .authentication import Authenticator, AuthnResult
from .authorization import (
    CapabilityCheck, CapabilityDecision, check_capability,
)
from .canonical_request import CanonicalError, CanonicalRequest, snapshot_request
from .capability import Capability, CapabilityRegistry
from .decision import Decision
from .evidence import EvidenceError, EvidenceJournal
from .escalation import EscalationError, EscalationStore
from .policy import PolicySnapshot
from .principal import Principal
from .provenance import ProvenanceChecker, ProvenanceKind, ProvenanceResult
from .grant import GrantError, ReasonClass, ReservedGrantStore, scope_hash
from .domain import (
    ActionType,
    EscalationStatus,
    OWNER_PRINCIPAL_ID,
    RiskLevel,
    Role,
    Verdict,
)


class Mediator:
    """Central authorization chokepoint.

    Does not execute actions. Only authorizes.
    All requests flow through: canonicalize -> authenticate -> dispatch.
    """

    def __init__(
        self,
        authenticator: Authenticator,
        registry: CapabilityRegistry,
        audit: AuditLog,
        provenance: ProvenanceChecker,
        policy: Optional[PolicySnapshot] = None,
        *,
        available: bool = True,
        policy_token: Optional["ProvisioningToken"] = None,
        require_principal_context: bool = False,
    ) -> None:
        self._authn = authenticator
        self._registry = registry
        self._audit = audit
        self._provenance = provenance
        self._policy = policy
        self.available = available
        # R1. Ar den pa bounder varje verdikt auktoriteten av den bundna
        # PrincipalContextens mandat, och ett saknat context ar ett nej. Den ar
        # av som standard: att sla pa den utan att ha satt contexter skulle
        # neka allt hos varje befintlig integrator. Med flaggan av finns inget
        # provenanstak alls -- det ar en deklarerad lucka, inte ett smyghal,
        # och den star utskriven i docs/ROADMAP.md R1.
        self.require_principal_context = require_principal_context
        self._escalations = EscalationStore()
        self._evidence = EvidenceJournal()
        self._grants = ReservedGrantStore()
        self._policy_sealed = False
        self._policy_bound_id = policy_token.token_id if policy_token is not None else None
        self._policy_token_ref = policy_token

    def set_policy(self, policy: Optional[PolicySnapshot], token: "ProvisioningToken") -> None:
        """Bootstrap-only policy setter."""
        from .provisioning import require_token, bind_token
        require_token(token, self._policy_sealed)
        self._policy_bound_id = bind_token(self._policy_bound_id, token)
        self._policy = policy

    def seal_policy(self, token: "ProvisioningToken") -> None:
        """Seal the policy provisioning path."""
        from .provisioning import require_token, bind_token
        require_token(token, self._policy_sealed)
        self._policy_bound_id = bind_token(self._policy_bound_id, token)
        self._policy_sealed = True

    def set_available(self, available: bool) -> None:
        self.available = available

    def evaluate(self, request) -> Decision:
        """Evaluate an action request."""
        return self._gated("evaluate", request, self._evaluate_authenticated)

    def reenter(self, request) -> Decision:
        """Reenter after Owner decision."""
        return self._gated("reenter", request, self._reenter_authenticated)

    def decide_escalation(self, request) -> Decision:
        """Owner decides on an escalation."""
        return self._gated("decide", request, self._decide_authenticated)

    def create_evidence(self, request) -> Decision:
        """Create candidate evidence."""
        return self._gated("evidence.create", request, self._create_evidence_authenticated)

    def verify_evidence(self, request) -> Decision:
        """Verify evidence."""
        return self._gated("evidence.verify", request, self._verify_evidence_authenticated)

    def authorize_evidence(self, request) -> Decision:
        """Authorize evidence."""
        return self._gated("evidence.authorize", request, self._authorize_evidence_authenticated)

    def update_policy(self, request) -> Decision:
        """Mediated, authenticated Owner policy update."""
        return self._gated("update_policy", request, self._update_policy_authenticated)

    def _gated(self, op: str, request, then) -> Decision:
        """Common gate: canonicalize -> authenticate -> dispatch."""
        if not self.available:
            dummy = _empty_canon()
            return self._finish(
                Verdict.DENY, "Mediator unavailable", ["mediator.unavailable"], dummy, None
            )
        try:
            canon = snapshot_request(request)
        except (CanonicalError, ValueError, TypeError, Exception) as exc:
            dummy = _empty_canon()
            return self._finish(
                Verdict.DENY, f"canonicalization failed: {exc}", ["canon.failed"], dummy, None
            )
        try:
            authn = self._authn.authenticate(canon)
        except Exception as exc:
            return self._finish(
                Verdict.DENY, f"authentication error: {exc}", ["authn.error"], canon, None
            )
        if not authn.ok or authn.principal is None:
            return self._finish(Verdict.DENY, authn.reason, [authn.rule], canon, authn.principal)
        try:
            return then(canon, authn)
        except Exception as exc:
            return self._finish(
                Verdict.DENY, f"fail-closed: {exc}", [f"{op}.error"], canon, authn.principal
            )

    def _evaluate_authenticated(self, canon: CanonicalRequest, authn: AuthnResult) -> Decision:
        principal = authn.principal
        assert principal is not None
        parsed = self._parse_action(canon, principal)
        if isinstance(parsed, Decision):
            return parsed
        action, domain, risk = parsed

        policy_decision = self._policy_gate(canon, principal, ["evaluate"])
        if policy_decision is not None:
            return policy_decision

        active_caps = self._registry.active_for(principal.principal_id)
        if not active_caps:
            active_caps = self._registry.for_principal(principal.principal_id)
            if not active_caps:
                active_caps = [None]

        best_check = None
        best_cap = None
        for cap in active_caps:
            check = check_capability(
                principal, cap, action, domain, risk,
                require_context=self.require_principal_context)
            if best_check is None:
                best_check = check
                best_cap = cap
            elif check.decision == CapabilityDecision.ALLOW:
                best_check = check
                best_cap = cap
                break
            elif check.decision == CapabilityDecision.OWNER_MANDATORY and best_check.decision == CapabilityDecision.DENY:
                best_check = check
                best_cap = cap

        cap = best_cap
        check = best_check
        rules = [authn.rule] + check.rules

        if check.decision is CapabilityDecision.DENY:
            return self._finish(
                Verdict.DENY, check.reason, rules, canon, principal,
                frame=check)

        if check.decision is CapabilityDecision.OWNER_MANDATORY:
            reason_class = (
                ReasonClass.OWNER_MANDATORY_ACTION
                if "authz.owner_mandatory_action" in check.rules
                else ReasonClass.OWNER_MANDATORY_RISK
            )
            return self._escalate(
                canon, principal, check.reason, rules, reason_class, cap,
                frame=check,
            )

        return self._permit_if_provenance(
            canon, principal, rules, check.reason, cap,
            frame=check)

    def _reenter_authenticated(self, canon: CanonicalRequest, authn: AuthnResult) -> Decision:
        principal = authn.principal
        assert principal is not None
        escalation_id = canon.get("escalation_id")
        if not escalation_id:
            return self._finish(
                Verdict.DENY, "reentry requires escalation_id", ["reentry.missing_id"], canon, principal
            )
        record = self._escalations.get(str(escalation_id))
        if record is None:
            return self._finish(
                Verdict.DENY, "escalation not found", ["reentry.not_found"], canon, principal
            )
        if record.status is EscalationStatus.PENDING:
            return self._finish(
                Verdict.DENY, "Owner has not decided", ["reentry.pending"], canon, principal,
                escalation_id=record.escalation_id,
            )
        if record.owner_decision != "permit":
            return self._finish(
                Verdict.DENY, f"Owner decided {record.owner_decision}", ["reentry.owner_deny"],
                canon, principal, escalation_id=record.escalation_id,
            )
        if record.status is EscalationStatus.RESOLVED:
            return self._finish(
                Verdict.DENY, "escalation already resolved", ["reentry.already_resolved"],
                canon, principal, escalation_id=record.escalation_id,
            )
        if principal.principal_id != record.principal_id:
            return self._finish(
                Verdict.DENY, "reentry principal mismatch", ["reentry.principal_mismatch"],
                canon, principal, escalation_id=record.escalation_id,
            )

        parsed = self._parse_action(canon, principal)
        if isinstance(parsed, Decision):
            return parsed
        action, domain, risk = parsed

        policy_decision = self._policy_gate(
            canon, principal, ["reentry", authn.rule], escalation_id=record.escalation_id
        )
        if policy_decision is not None:
            return policy_decision

        grant = self._grants.get_by_escalation(record.escalation_id)
        if grant and grant.capability_id:
            cap = self._registry.get(grant.capability_id)
        else:
            active_caps = self._registry.active_for(principal.principal_id) or self._registry.for_principal(principal.principal_id) or [None]
            best_check = None
            best_cap = None
            for c in active_caps:
                chk = check_capability(
                    principal, c, action, domain, risk,
                    require_context=self.require_principal_context)
                if best_check is None or chk.decision == CapabilityDecision.ALLOW or (chk.decision == CapabilityDecision.OWNER_MANDATORY and best_check.decision == CapabilityDecision.DENY):
                    best_check = chk
                    best_cap = c
                    if chk.decision == CapabilityDecision.ALLOW:
                        break
            cap = best_cap

        skip = False
        if grant is not None and grant.owner_decision == "permit" and not grant.consumed:
            if grant.reason_class is ReasonClass.OWNER_MANDATORY_ACTION and grant.action == action.value:
                skip = True
            elif grant.reason_class is ReasonClass.OWNER_MANDATORY_RISK and grant.risk_level == risk.value:
                skip = True

        check = check_capability(
            principal, cap, action, domain, risk, skip_owner_mandatory_escalate=skip,
            require_context=self.require_principal_context,
        )
        rules = [authn.rule, "reentry.escalation_matched"] + check.rules
        if check.decision is not CapabilityDecision.ALLOW:
            return self._finish(
                Verdict.DENY, check.reason, rules, canon, principal,
                escalation_id=record.escalation_id,
                frame=check,
            )

        # Bind reserved grant before PERMIT
        try:
            prov = self._provenance.check()
        except Exception as exc:
            return self._finish(
                Verdict.ESCALATE, f"provenance unavailable: {exc}",
                rules + ["provenance.unavailable"], canon, principal,
                escalation_id=record.escalation_id,
                frame=check,
            )
        if not (prov.kind == ProvenanceKind.MATCH and prov.ok):
            if prov.kind == ProvenanceKind.MISMATCH:
                return self._finish(
                    Verdict.DENY, prov.reason, rules + ["provenance.mismatch"],
                    canon, principal, escalation_id=record.escalation_id,
                    frame=check,
                )
            return self._finish(
                Verdict.ESCALATE, prov.reason, rules + ["provenance.unavailable"],
                canon, principal, escalation_id=record.escalation_id,
                frame=check,
            )

        policy = self._policy
        policy_hash = policy.hash if policy is not None else ""
        try:
            self._grants.consume_if_valid(
                record.escalation_id,
                principal_id=principal.principal_id,
                agent_id=str(canon.get("agent_id") or ""),
                request_id=str(canon.get("request_id") or ""),
                action=action.value,
                domain=domain,
                risk_level=risk.value,
                payload_hash=canon.full_payload_hash(),
                capability_id=cap.capability_id if cap else "",
                capability_scope_hash=scope_hash(cap) if cap else "",
                policy_hash=policy_hash,
                provenance_identity=prov.identity,
            )
        except GrantError as exc:
            return self._finish(
                Verdict.DENY, str(exc), rules + ["grant.rejected"], canon, principal,
                escalation_id=record.escalation_id,
                frame=check,
            )

        if prov.head_drift:
            rules = rules + ["provenance.head_drift_diagnostic"]
        decision = self._permit(canon, principal, rules + ["provenance.ok"], "reentry authorized",
                                record.escalation_id, frame=check)
        if decision.verdict is Verdict.PERMIT:
            try:
                self._escalations.mediator_resolve(record.escalation_id)
            except EscalationError:
                pass
        return decision

    def _decide_authenticated(self, canon: CanonicalRequest, authn: AuthnResult) -> Decision:
        principal = authn.principal
        assert principal is not None
        if principal.principal_id != OWNER_PRINCIPAL_ID:
            return self._finish(
                Verdict.DENY, "Owner decision requires Owner principal",
                ["decide.not_owner"], canon, principal,
            )
        cap = self._select_capability(principal, role=Role.R_DEC)
        if cap is None or cap.role is not Role.R_DEC or not cap.is_active():
            return self._finish(
                Verdict.DENY, "Owner principal is not authorized (R-DEC)",
                ["decide.not_authorized"], canon, principal,
            )
        escalation_id = canon.get("escalation_id")
        decision = canon.get("owner_decision")
        if decision not in ("permit", "deny"):
            return self._finish(
                Verdict.DENY, "owner_decision must be permit or deny",
                ["decide.invalid_value"], canon, principal,
            )
        try:
            record = self._escalations.mediator_decide(
                str(escalation_id), str(decision), principal.principal_id
            )
        except EscalationError as exc:
            return self._finish(Verdict.DENY, str(exc), ["decide.rejected"], canon, principal)
        self._grants.attach_owner_decision(record.escalation_id, str(decision))
        reason = (
            "Owner permit recorded; execution grant requires reentry"
            if decision == "permit"
            else "Owner denied; action remains blocked"
        )
        return self._finish(
            Verdict.DENY, reason, [authn.rule, "decide.recorded"], canon, principal,
            escalation_id=record.escalation_id, owner_decision=str(decision),
        )

    def _update_policy_authenticated(self, canon: CanonicalRequest, authn: AuthnResult) -> Decision:
        principal = authn.principal
        assert principal is not None
        if principal.principal_id != OWNER_PRINCIPAL_ID:
            return self._finish(
                Verdict.DENY, "policy update requires Owner principal",
                ["policy.update_not_owner"], canon, principal,
            )
        cap = self._select_capability(principal, role=Role.R_DEC)
        if cap is None or cap.role is not Role.R_DEC or not cap.is_active():
            return self._finish(
                Verdict.DENY, "Owner principal is not authorized (R-DEC)",
                ["policy.update_not_authorized"], canon, principal,
            )
        policy_version = canon.get("policy_version")
        policy_body = canon.get("policy_body")
        if not isinstance(policy_version, str) or not policy_version:
            return self._finish(
                Verdict.DENY, "policy_version required",
                ["policy.update_bad_request"], canon, principal,
            )
        if not isinstance(policy_body, dict):
            return self._finish(
                Verdict.DENY, "policy_body must be a dict",
                ["policy.update_bad_request"], canon, principal,
            )
        new_policy = PolicySnapshot.from_body(policy_version, policy_body)
        if new_policy.blocks_permit():
            return self._finish(
                Verdict.DENY, "proposed policy would block all permits",
                ["policy.update_rejected"], canon, principal,
            )
        self._policy = new_policy
        return self._finish(
            Verdict.DENY, f"policy updated to version {policy_version}",
            [authn.rule, "policy.updated"], canon, principal,
        )

    def _create_evidence_authenticated(self, canon: CanonicalRequest, authn: AuthnResult) -> Decision:
        principal = authn.principal
        assert principal is not None
        evidence_id = canon.get("evidence_id")
        content = canon.get("content")
        if not evidence_id:
            return self._finish(Verdict.DENY, "evidence_id required", ["evidence.bad_request"], canon, principal)
        try:
            self._evidence.create_candidate(str(evidence_id), principal.principal_id, content)
        except EvidenceError as exc:
            return self._finish(Verdict.DENY, str(exc), ["evidence.create_rejected"], canon, principal)
        return self._finish(
            Verdict.DENY, "candidate recorded; evidence is not authority",
            [authn.rule, "evidence.candidate"], canon, principal,
        )

    def _verify_evidence_authenticated(self, canon: CanonicalRequest, authn: AuthnResult) -> Decision:
        principal = authn.principal
        assert principal is not None
        cap = self._select_capability(principal, role=Role.R_IV)
        role = cap.role if cap and cap.is_active() else None
        if role is None:
            return self._finish(Verdict.DENY, "no active capability", ["evidence.no_capability"], canon, principal)
        evidence_id = canon.get("evidence_id")
        if not evidence_id:
            return self._finish(Verdict.DENY, "evidence_id required", ["evidence.bad_request"], canon, principal)
        result = canon.get("verification_result")
        try:
            record = self._evidence.verify(str(evidence_id), principal, role, result)
        except EvidenceError as exc:
            return self._finish(Verdict.DENY, str(exc), ["evidence.verify_rejected"], canon, principal)
        return self._finish(
            Verdict.DENY, f"verification recorded; state={record.state.value}",
            [authn.rule, "evidence.verified" if result is True else "evidence.verification_failed"], canon, principal,
        )

    def _authorize_evidence_authenticated(self, canon: CanonicalRequest, authn: AuthnResult) -> Decision:
        principal = authn.principal
        assert principal is not None
        cap = self._select_capability(principal, role=Role.R_DEC)
        role = cap.role if cap and cap.is_active() else None
        if role is None:
            return self._finish(Verdict.DENY, "no active capability", ["evidence.no_capability"], canon, principal)
        evidence_id = canon.get("evidence_id")
        if not evidence_id:
            return self._finish(Verdict.DENY, "evidence_id required", ["evidence.bad_request"], canon, principal)
        result = canon.get("authorization_result")
        try:
            record = self._evidence.authorize(str(evidence_id), principal, role, result)
        except EvidenceError as exc:
            return self._finish(Verdict.DENY, str(exc), ["evidence.authorize_rejected"], canon, principal)
        return self._finish(
            Verdict.DENY, f"evidence authorization recorded; state={record.state.value}",
            [authn.rule, "evidence.authorized" if result is True else "evidence.authorization_failed"], canon, principal,
        )

    def evidence_state(self, evidence_id: str):
        return self._evidence.get(evidence_id)

    def evidence_events(self):
        return self._evidence.events()

    def get_escalation(self, escalation_id: str):
        return self._escalations.get(escalation_id)

    def _select_capability(self, principal: Principal, role: Optional[Role] = None) -> Optional[Capability]:
        active = self._registry.active_for(principal.principal_id)
        if role is not None:
            active = [c for c in active if c.role == role]
        if active:
            return active[0]
        bound = self._registry.for_principal(principal.principal_id)
        if role is not None:
            bound = [c for c in bound if c.role == role]
        return bound[0] if bound else None

    def _parse_action(self, canon: CanonicalRequest, principal: Optional[Principal] = None):
        try:
            action = ActionType(canon.get("action_type"))
        except (ValueError, KeyError, TypeError):
            return self._finish(
                Verdict.DENY, "invalid action_type", ["schema.action_type"], canon, principal
            )
        domain = canon.get("domain")
        if not isinstance(domain, str) or not domain:
            return self._finish(Verdict.DENY, "domain required", ["schema.domain"], canon, principal)
        risk_raw = canon.get("risk_level")
        if risk_raw is None or risk_raw == "":
            return self._finish(Verdict.DENY, "risk_level required", ["schema.risk_missing"], canon, principal)
        try:
            risk = RiskLevel(risk_raw)
        except (ValueError, KeyError, TypeError):
            return self._finish(Verdict.DENY, "invalid risk_level", ["schema.risk"], canon, principal)
        return action, domain, risk

    def _policy_identity(self) -> Tuple[str, str]:
        if self._policy is None:
            return "", ""
        return self._policy.version, self._policy.hash

    def _policy_gate(
        self,
        canon: CanonicalRequest,
        principal: Principal,
        rules: List[str],
        escalation_id: Optional[str] = None,
    ) -> Optional[Decision]:
        if self._policy is None or self._policy.blocks_permit():
            reason = "policy missing, placeholder, or corrupt"
            return self._escalate(
                canon, principal, reason, list(rules) + ["policy.blocks_permit"],
                ReasonClass.POLICY, None,
                existing_id=escalation_id,
            )
        return None

    def _escalate(
        self,
        canon: CanonicalRequest,
        principal: Principal,
        reason: str,
        rules: List[str],
        reason_class: ReasonClass,
        cap: Optional[Capability],
        existing_id: Optional[str] = None,
        frame: Optional[CapabilityCheck] = None,
    ) -> Decision:
        parsed = self._parse_action(canon, principal)
        action_s = domain = risk_s = ""
        if not isinstance(parsed, Decision):
            action, domain, risk = parsed
            action_s, risk_s = action.value, risk.value
        if existing_id:
            escalation_id = existing_id
        else:
            escalation_id = f"esc-{uuid4().hex[:12]}"
            payload_hash = canon.full_payload_hash()
            self._escalations.create(
                escalation_id=escalation_id,
                request_id=str(canon.get("request_id") or ""),
                principal_id=principal.principal_id,
                payload_hash=payload_hash,
                reason=reason,
                reason_class=reason_class.value,
            )
            version, phash = self._policy_identity()
            try:
                prov = self._provenance.check()
                pkind = prov.kind
                pident = prov.identity
            except Exception:
                pkind, pident = ProvenanceKind.UNAVAILABLE, ""
            self._grants.create_pending_context(
                escalation_id=escalation_id,
                principal_id=principal.principal_id,
                agent_id=str(canon.get("agent_id") or ""),
                request_id=str(canon.get("request_id") or ""),
                action=action_s,
                domain=domain or "",
                risk_level=risk_s,
                payload_hash=canon.full_payload_hash(),
                capability_id=cap.capability_id if cap else "",
                capability_scope_hash=scope_hash(cap) if cap else "",
                policy_version=version,
                policy_hash=phash,
                provenance_kind=pkind,
                provenance_identity=pident,
                reason_class=reason_class,
            )
        return self._finish(
            Verdict.ESCALATE, reason, rules + ["escalate.created"], canon, principal,
            escalation_id=escalation_id, frame=frame,
        )

    def _permit_if_provenance(
        self,
        canon: CanonicalRequest,
        principal: Principal,
        rules: List[str],
        reason: str,
        cap: Optional[Capability],
        escalation_id: Optional[str] = None,
        frame: Optional[CapabilityCheck] = None,
    ) -> Decision:
        try:
            prov: ProvenanceResult = self._provenance.check()
        except Exception as exc:
            return self._escalate(
                canon, principal, f"provenance unavailable: {exc}",
                rules + ["provenance.unavailable"], ReasonClass.PROVENANCE, cap,
                existing_id=escalation_id, frame=frame,
            )
        if not (isinstance(prov.kind, str) and prov.kind == ProvenanceKind.MATCH and prov.ok):
            if prov.kind == ProvenanceKind.MISMATCH:
                return self._finish(
                    Verdict.DENY, prov.reason, rules + ["provenance.mismatch"],
                    canon, principal, escalation_id=escalation_id, frame=frame,
                )
            return self._escalate(
                canon, principal, prov.reason or "provenance not established",
                rules + ["provenance.unavailable"], ReasonClass.PROVENANCE, cap,
                existing_id=escalation_id, frame=frame,
            )
        if prov.head_drift:
            rules = rules + ["provenance.head_drift_diagnostic"]
        return self._permit(
            canon, principal, rules + ["provenance.ok"], reason, escalation_id, frame)

    def _permit(
        self,
        canon: CanonicalRequest,
        principal: Principal,
        rules: List[str],
        reason: str,
        escalation_id: Optional[str],
        frame: Optional[CapabilityCheck] = None,
    ) -> Decision:
        grant = {
            "request_id": canon.get("request_id"),
            "principal_id": principal.principal_id,
            "action_type": canon.get("action_type"),
            "domain": canon.get("domain"),
            "risk_level": canon.get("risk_level"),
        }
        return self._finish(
            Verdict.PERMIT, reason, rules, canon, principal,
            grant=grant, escalation_id=escalation_id, frame=frame,
        )

    def _audit_record(self, verdict, reason, rules, canon, bound,
                      escalation_id, owner_decision, frame=None) -> dict:
        """Beskrivningen av ett beslut som gar in i auditkedjan.

        R1 villkor 2: en lasare ska kunna se VILKEN ram som gallde, inte bara
        utfallet. Ramen kommer fran `frame` -- den CapabilityCheck som faktiskt
        avgjorde -- och lases INTE om ur contexten har. Skillnaden ar inte
        kosmetisk: mellan check_capability och den har raden kor
        `self._provenance.check()`, en injicerad beroende. Las vi contexten pa
        nytt kan en trasig eller illvillig backend ha bytt ut den under tiden,
        och loggen skulle da beskriva en annan ram an den som gav beslutet.
        En sanningskalla per berakning, och den kallan ar checken.
        """
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": canon.get("request_id"),
            "bound_principal": bound,
            "agent_id_claim": canon.get("agent_id"),
            "action_type": canon.get("action_type"),
            "domain": canon.get("domain"),
            "risk_level": canon.get("risk_level"),
            "verdict": verdict.value,
            "reason": reason,
            "applied_rules": list(rules),
            "escalation_id": escalation_id,
            "owner_decision": owner_decision,
            "execution_granted": verdict is Verdict.PERMIT,
            "payload_hash": canon.full_payload_hash(),
            # Ett saknat varde ar inte noll och inte "ingen begransning" -- det
            # ar frånvaron av en uppgift, och skrivs som None.
            "provenance": frame.provenance if frame is not None else None,
            "mandate_id": frame.mandate_id if frame is not None else None,
            "effective_risk_ceiling": (
                frame.effective_risk_ceiling.value
                if frame is not None and frame.effective_risk_ceiling is not None
                else None),
        }

    def _finish(
        self,
        verdict: Verdict,
        reason: str,
        rules: List[str],
        canon: CanonicalRequest,
        principal: Optional[Principal],
        grant: Optional[dict] = None,
        escalation_id: Optional[str] = None,
        owner_decision: Optional[str] = None,
        frame: Optional[CapabilityCheck] = None,
    ) -> Decision:
        if verdict is Verdict.PERMIT and grant is None:
            verdict = Verdict.DENY
            reason = "internal: PERMIT without grant"
            rules = list(rules) + ["permit.missing_grant"]

        bound = _safe_principal_id(principal)

        try:
            record = self._audit_record(
                verdict, reason, rules, canon, bound, escalation_id, owner_decision,
                frame)
        except Exception as exc:
            # Sista natet. Bygget av auditposten lag tidigare utanfor varje try:
            # ett canon eller ett principal-objekt som inte betedde sig som
            # kernan antog tog sig hela vagen ut ur evaluate() som ett undantag.
            # Kan vi inte ens beskriva beslutet finns ingen tillit kvar att ge
            # bort -- och _gated:s egen fallback gar ocksa genom har.
            if escalation_id:
                try:
                    self._grants.unconsume(escalation_id)
                except Exception:
                    pass
            return Decision(
                verdict=Verdict.DENY,
                reason=f"fail-closed: audit record could not be built: {exc}",
                applied_rules=list(rules) + ["record.build_failed"],
                bound_principal=bound,
                grant=None,
                escalation_id=escalation_id,
                audit_hash=None,
                owner_decision=owner_decision,
            )

        audit_hash = None
        try:
            audit_hash = self._audit.append(record)
        except Exception as exc:
            # AuditLog.append packar sina egna fel i AuditError, men audit ar en
            # injicerad beroende: vilket objekt som helst med .append() duger.
            # Ett OSError fran en annan backend gick tidigare rakt igenom -- och
            # eftersom _gated:s fallback ocksa gar via _finish kom den ut ur
            # evaluate() som ett undantag i stallet for ett DENY. Fail-closed
            # kraver att varje utgang har ar ett verdikt.
            if escalation_id:
                try:
                    self._grants.unconsume(escalation_id)
                except Exception:
                    pass
            if verdict is Verdict.PERMIT:
                return Decision(
                    verdict=Verdict.DENY,
                    reason=f"audit write failed: {exc}",
                    applied_rules=list(rules) + ["audit.write_failed"],
                    bound_principal=bound,
                    grant=None,
                    escalation_id=escalation_id,
                    audit_hash=None,
                    owner_decision=owner_decision,
                )
            rules = list(rules) + ["audit.write_failed"]
            return Decision(
                verdict=verdict,
                reason=reason,
                applied_rules=rules,
                bound_principal=bound,
                grant=None,
                escalation_id=escalation_id,
                audit_hash=None,
                owner_decision=owner_decision,
            )

        if verdict is Verdict.PERMIT and not audit_hash:
            return Decision(
                verdict=Verdict.DENY,
                reason="audit hash missing",
                applied_rules=list(rules) + ["audit.hash_missing"],
                bound_principal=bound,
                grant=None,
                escalation_id=escalation_id,
            )

        return Decision(
            verdict=verdict,
            reason=reason,
            applied_rules=list(rules),
            bound_principal=bound,
            grant=grant if verdict is Verdict.PERMIT else None,
            escalation_id=escalation_id,
            audit_hash=audit_hash,
            owner_decision=owner_decision,
        )


def _safe_principal_id(principal: Optional[Principal]) -> Optional[str]:
    """Las principal-id:t utan att kunna kasta.

    Authenticator ar ett injicerat beroende precis som audit: konstruktorn tar
    emot vilket objekt som helst med .authenticate(), sa det som kommer tillbaka
    behover inte vara en Principal. _finish far inte fallera pa att beskriva den
    som just nekades -- ett okant id ar None, aldrig ett undantag.
    """
    try:
        pid = principal.principal_id if principal is not None else None
    except Exception:
        return None
    return pid if isinstance(pid, str) else None


def _empty_canon() -> CanonicalRequest:
    from types import MappingProxyType
    return CanonicalRequest(MappingProxyType({}), "{}")
