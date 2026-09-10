------------------------------ MODULE GovernanceInvariantsV6 ------------------------------
EXTENDS GovernanceV6

\* I1: Observability
I1_Observability ==
  \A den \in DOMAIN enforceLog:
    \E i \in 1..Len(obsLog):
      IdentityBound(obsLog[i], enforceLog[den])

\* I2: Deniability - every executed action authorized for its resource
I2_Deniability ==
  \A exec \in DOMAIN execLog:
    \E a \in Authority:
      AuthResource(execLog[exec].action, execLog[exec].resource, a)

\* I3: Immutability
I3_Immutability ==
  bootstrapDone =>
    \A a \in Authority: authPolicy[a] = initPolicy[a]

\* I4: Temporal ordering - observation before enforcement
I4_TemporalOrdering ==
  \A den \in DOMAIN enforceLog:
    \E i \in 1..Len(obsLog):
      /\ IdentityBound(obsLog[i], enforceLog[den])
      /\ ObsBeforeEnf(obsLog[i], enforceLog[den])

\* I5: Completeness - executed actions have observations
I5_Completeness ==
  \A exec \in DOMAIN execLog:
    \E i \in 1..Len(obsLog):
      /\ obsLog[i].uid = execLog[exec].uid
      /\ obsLog[i].entity = execLog[exec].entity
      /\ obsLog[i].action = execLog[exec].action
      /\ obsLog[i].resource = execLog[exec].resource

\* I6: Consistency
I6_Consistency ==
  \A den \in DOMAIN enforceLog:
    \E i \in 1..Len(obsLog):
      IdentityBound(obsLog[i], enforceLog[den])

\* I7: External authority
I7_ExternalAuthority ==
  \A e \in Entity, a \in Authority: a # e

\* I8: Semantic correctness - intent matches policy
I8_SemanticCorrectness ==
  bootstrapDone =>
    \A a \in Authority: SemanticallyCorrect(a)

\* I9: Trust verification
I9_TrustVerification ==
  \A den \in DOMAIN enforceLog:
    \E a \in Authority: Trusted(a)

\* I10: Enforcement before execution
I10_EnfBeforeExec ==
  \A exec \in DOMAIN execLog:
    \E i \in 1..Len(enforceLog):
      /\ enforceLog[i].uid = execLog[exec].uid
      /\ enforceLog[i].decision = "ALLOWED"
      /\ EnfBeforeExec(enforceLog[i], execLog[exec])

\* Safety properties
NoUnauthorizedExecution ==
  \A exec \in DOMAIN execLog:
    \E a \in Authority:
      /\ AuthResource(execLog[exec].action, execLog[exec].resource, a)
      /\ Trusted(a)

ObservationBeforeEnforcement == I4_TemporalOrdering

ObservationBeforeExecution ==
  \A exec \in DOMAIN execLog:
    \E i \in 1..Len(obsLog):
      /\ obsLog[i].uid = execLog[exec].uid
      /\ ObsBeforeExec(obsLog[i], execLog[exec])

\* Combined
GovernanceSecurityBoundary ==
  I1_Observability /\ I2_Deniability /\ I3_Immutability /\
  I4_TemporalOrdering /\ I5_Completeness /\ I6_Consistency /\
  I7_ExternalAuthority /\ I8_SemanticCorrectness /\
  I9_TrustVerification /\ I10_EnfBeforeExec

=============================================================================
