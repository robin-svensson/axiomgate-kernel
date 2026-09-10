"""AxiomGate Kernel — Authorization Check

Internal capability check. Not a grant authority.

Since 2026-09-10 it also bounds the authority by *how* a call arose, not
just by what the agent is named: the effective risk ceiling is the lower of
the capability's own ceiling and the ceiling carried by the mandate the
bound PrincipalContext holds. See docs/ROADMAP.md R1.
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

    `effective_risk_ceiling` is None as long as no effective ceiling has been
    computed: when no context was required, and when the context was rejected before
    any ceiling comparison took place (missing, unparseable, invalid, or out-of-scope
    mandate). A missing value is not a ceiling, it is the absence of one. `mandate_id`
    is None until a mandate has been parsed -- after that it stays set even when the
    mandate was denied, so a reader sees WHICH mandate was not enough.
    """
    decision: CapabilityDecision
    reason: str
    rules: List[str]
    capability_id: Optional[str] = None
    effective_risk_ceiling: Optional[RiskLevel] = None
    mandate_id: Optional[str] = None
    provenance: Optional[str] = None


def _prov(ctx: Optional[PrincipalContext]) -> Optional[str]:
    """The provenance from the context the check actually tested against, or None.

    It gets stuck onto CapabilityCheck so the audit record does not need to
    re-read the context afterward -- see Mediator._audit_record.
    """
    return ctx.provenance if ctx is not None else None


def bound_context() -> Optional[PrincipalContext]:
    """The bound context, or None. Must never throw.

    Reading the ContextVar is injected environment in the same way as audit:
    it must not be able to escape a verdict as an exception.
    """
    try:
        return get_principal_context()
    except Exception:
        return None


def effective_ceiling(cap_ceiling: RiskLevel, mandate: Mandate) -> RiskLevel:
    """The lower of two ceilings. A single source of truth for the minimum rule."""
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

    # R1. An unbound context is a graver error than a missing capability: it
    # means the kernel does not know how the call arose. It must therefore
    # never fall back to "no ceiling" -- that would be fail-open in the one
    # direction no one detects, since the outcome then looks normal.
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

    # The finding from 2026-09-10: this line used to be `capability.risk_ceiling`,
    # so every downstream return that never reached effective_ceiling() was writing
    # the CAPABILITY's ceiling into a field called effective_risk_ceiling -- both
    # when the mandate was denied on scope or validity, and throughout the unflagged
    # path where there is by definition no provenance frame at all. A missing value
    # is not a ceiling. Now `ceiling` is set from a single source,
    # effective_ceiling(), and is None until it is computed.
    ceiling: Optional[RiskLevel] = None
    mandate_id = None
    if require_context:
        # The gate at the top has already rejected an invalid context. Asking
        # again is not redundant: relying on that one gate alone would turn a
        # missing context into an AttributeError instead of a verdict, and a
        # 'fail-closed: ' with no reason is not an answer a reviewer can read.
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
            # parse_mandate returns None both for an unknown scope and for a
            # tail it does not recognize. Both are the same error: the string
            # says something we cannot verify, and then it is not a mandate.
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
