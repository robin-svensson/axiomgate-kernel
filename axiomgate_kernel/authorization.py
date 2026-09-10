"""AxiomGate Kernel — Authorization Check

Internal capability check. Not a grant authority.

Sedan 2026-09-10 bounder den ocksa auktoriteten av *hur* ett anrop uppstod,
inte bara av vad agenten heter: det effektiva risktaket ar det lagsta av
capabilityns eget tak och taket i det mandat den bundna PrincipalContext
bar. Se docs/ROADMAP.md R1.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from .capability import Capability
from .principal import Principal
from .principal_context import (
    Mandate,
    PrincipalContext,
    get_principal_context,
    is_principal_valid,
    parse_mandate,
)
from .domain import (
    ActionType,
    OWNER_MANDATORY_ACTIONS,
    OWNER_PRINCIPAL_ID,
    RiskLevel,
    Role,
)


class CapabilityDecision(Enum):
    """Internal disposition. Mediator maps this to Verdict + grant."""
    ALLOW = "ALLOW"
    DENY = "DENY"
    OWNER_MANDATORY = "OWNER_MANDATORY"


@dataclass
class CapabilityCheck:
    """Result of a capability check.

    `effective_risk_ceiling` ar None sa lange inget effektivt tak har raknats
    fram: nar ingen context kravdes, och nar contexten avvisades innan nagon
    takjamforelse skedde (saknat, otolkbart, ogiltigt eller ur-scope mandat).
    Ett saknat varde ar inte ett tak, det ar frånvaron av ett. `mandate_id` ar
    None till dess ett mandat har tolkats -- darefter star det kvar aven nar
    mandatet nekades, sa att en lasare ser VILKET mandat som inte rackte.
    """
    decision: CapabilityDecision
    reason: str
    rules: List[str]
    capability_id: Optional[str] = None
    effective_risk_ceiling: Optional[RiskLevel] = None
    mandate_id: Optional[str] = None
    provenance: Optional[str] = None


def _prov(ctx: Optional[PrincipalContext]) -> Optional[str]:
    """Provenansen ur den context checken faktiskt provade mot, eller None.

    Den fastnar i CapabilityCheck sa att auditposten slipper lasa om
    contexten efterat -- se Mediator._audit_record.
    """
    return ctx.provenance if ctx is not None else None


def bound_context() -> Optional[PrincipalContext]:
    """Den bundna contexten, eller None. Far aldrig kasta.

    ContextVar-lasningen ar injicerad omvarld pa samma satt som audit: den ska
    inte kunna ta sig ut ur ett verdikt som ett undantag.
    """
    try:
        return get_principal_context()
    except Exception:
        return None


def effective_ceiling(cap_ceiling: RiskLevel, mandate: Mandate) -> RiskLevel:
    """Det lagsta av tva tak. En sanningskalla for minimum-regeln."""
    return cap_ceiling if cap_ceiling.rank <= mandate.risk_ceiling.rank else mandate.risk_ceiling


def _is_owner(principal: Principal) -> bool:
    """Check if principal is the Owner."""
    return principal.principal_id == OWNER_PRINCIPAL_ID


def check_capability(
    principal: Principal,
    capability: Optional[Capability],
    action: ActionType,
    domain: str,
    risk: RiskLevel,
    *,
    skip_owner_mandatory_escalate: bool = False,
    require_context: bool = False,
) -> CapabilityCheck:
    """Evaluate capability rules.

    Does not authenticate, audit, or grant.
    Returns internal disposition for Mediator to map.
    """
    rules: List[str] = ["authz.entered"]

    # R1. En obunden context ar ett grovre fel an ett saknat capability: den
    # betyder att kernan inte vet hur anropet uppstod. Den far darfor aldrig
    # falla tillbaka pa "inget tak" -- det vore fail-open i den ena riktning
    # som ingen upptacker, eftersom utfallet da ser normalt ut.
    ctx = bound_context() if require_context else None
    if require_context and not is_principal_valid(ctx):
        rules.append("authz.no_principal_context")
        return CapabilityCheck(
            CapabilityDecision.DENY, "no principal context bound", rules)

    if capability is None:
        rules.append("authz.no_capability")
        return CapabilityCheck(CapabilityDecision.DENY, "no capability", rules)

    if capability.principal_id != principal.principal_id:
        rules.append("authz.principal_mismatch")
        return CapabilityCheck(
            CapabilityDecision.DENY,
            "capability not bound to principal",
            rules,
            capability.capability_id,
        )

    if not capability.is_structurally_valid():
        rules.append("authz.capability_invalid")
        reason = "invalid capability"
        if capability.transferable:
            rules.append("authz.transferable")
            reason = "transferable capability rejected"
        elif capability.delegation_depth != 1:
            rules.append("authz.delegation_depth")
            reason = "delegation depth exceeds 1"
        elif capability.issued_by != "Owner":
            rules.append("authz.not_owner_issued")
            reason = "capability not issued by Owner"
        elif capability.role is Role.R_DEC and capability.principal_id != OWNER_PRINCIPAL_ID:
            rules.append("authz.rdec_not_owner")
            reason = "R-DEC is Owner-only"
        return CapabilityCheck(CapabilityDecision.DENY, reason, rules, capability.capability_id)

    if capability.is_revoked():
        rules.append("authz.revoked")
        return CapabilityCheck(CapabilityDecision.DENY, "capability revoked", rules, capability.capability_id)

    if capability.is_expired():
        rules.append("authz.expired")
        return CapabilityCheck(CapabilityDecision.DENY, "capability expired", rules, capability.capability_id)

    owner_mandatory = False
    if not _is_owner(principal):
        if action.value in OWNER_MANDATORY_ACTIONS:
            owner_mandatory = True
            rules.append("authz.owner_mandatory_action")
        elif risk is RiskLevel.HIGH:
            # HIGH risk requires Owner escalation (CRITICAL not in this version)
            owner_mandatory = True
            rules.append("authz.owner_mandatory_risk")

    if owner_mandatory and not skip_owner_mandatory_escalate:
        return CapabilityCheck(
            CapabilityDecision.OWNER_MANDATORY,
            "Owner-mandatory reservation required",
            rules,
            capability.capability_id,
        )
    if skip_owner_mandatory_escalate and owner_mandatory:
        rules.append("authz.reserved_grant_skip_escalate")

    if action not in capability.action_types:
        rules.append("authz.action_out_of_scope")
        return CapabilityCheck(
            CapabilityDecision.DENY,
            "action not in capability scope",
            rules,
            capability.capability_id,
        )

    if domain not in capability.domains:
        rules.append("authz.domain_out_of_scope")
        return CapabilityCheck(
            CapabilityDecision.DENY,
            "domain not in capability scope",
            rules,
            capability.capability_id,
        )

    if risk.exceeds(capability.risk_ceiling):
        rules.append("authz.risk_ceiling")
        return CapabilityCheck(
            CapabilityDecision.DENY,
            f"risk {risk.value} exceeds ceiling {capability.risk_ceiling.value}",
            rules,
            capability.capability_id,
        )

    # Fyndet 2026-09-10: den har radén var `capability.risk_ceiling`, och
    # varje nedstroms retur som inte hann fram till effective_ceiling() skrev
    # alltsa in CAPABILITYNS tak i ett falt som heter effective_risk_ceiling --
    # bade nar mandatet nekades pa scope eller giltighet, och i hela det
    # oflaggade laget dar det per definition inte finns nagon provenansram.
    # Ett saknat varde ar inte ett tak. Nu satts `ceiling` av en enda kalla,
    # effective_ceiling(), och ar None till dess den kort.
    ceiling: Optional[RiskLevel] = None
    mandate_id = None
    if require_context:
        # Grinden hogst upp har redan avvisat ett ogiltigt context. Att fraga
        # igen ar inte overflodigt: bar den ena grinden ensam blir ett saknat
        # context ett AttributeError i stallet for ett verdikt, och ett
        # 'fail-closed: ' utan reason ar inte ett svar en granskare kan lasa.
        if ctx is None:
            rules.append("authz.no_principal_context")
            return CapabilityCheck(
                CapabilityDecision.DENY, "no principal context bound",
                rules, capability.capability_id)
        if not ctx.mandate:
            rules.append("authz.no_mandate")
            return CapabilityCheck(
                CapabilityDecision.DENY,
                "no mandate bound to principal context",
                rules, capability.capability_id, None, None, _prov(ctx))

        mandate = parse_mandate(ctx.mandate)
        if mandate is None:
            # parse_mandate returnerar None bade for okand scope och for en
            # svans den inte kanner igen. Bada ar samma fel: strangen sager
            # nagot vi inte kan prova, och da ar den inte ett mandat.
            rules.append("authz.mandate_unparseable")
            return CapabilityCheck(
                CapabilityDecision.DENY,
                "mandate could not be parsed",
                rules, capability.capability_id, None, None, _prov(ctx))

        mandate_id = mandate.mandate_id
        if not mandate.is_valid:
            rules.append("authz.mandate_invalid")
            return CapabilityCheck(
                CapabilityDecision.DENY,
                "mandate expired or out of scope",
                rules, capability.capability_id, ceiling, mandate_id,
                _prov(ctx))

        if action not in mandate.action_types:
            rules.append("authz.mandate_action_out_of_scope")
            return CapabilityCheck(
                CapabilityDecision.DENY,
                f"action {action.value} not in mandate scope {mandate.scope}",
                rules, capability.capability_id, ceiling, mandate_id,
                _prov(ctx))

        ceiling = effective_ceiling(capability.risk_ceiling, mandate)
        if risk.exceeds(ceiling):
            rules.append("authz.provenance_risk_ceiling")
            return CapabilityCheck(
                CapabilityDecision.DENY,
                f"risk {risk.value} exceeds effective ceiling {ceiling.value} "
                f"(capability {capability.risk_ceiling.value}, "
                f"mandate {mandate.risk_ceiling.value})",
                rules, capability.capability_id, ceiling, mandate_id,
                _prov(ctx))

    rules.append("authz.allow")
    return CapabilityCheck(
        CapabilityDecision.ALLOW, "capability allows", rules,
        capability.capability_id, ceiling, mandate_id, _prov(ctx))
