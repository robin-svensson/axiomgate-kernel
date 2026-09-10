------------------------------ MODULE GovernanceV6 ------------------------------
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
  Authority,
  Entity,
  Actions,
  Resources

VARIABLES
  authPolicy,
  initPolicy,
  entityState,
  trustDomain,
  obsLog,
  execLog,
  enforceLog,
  intent,
  bootstrapDone,
  uidCounter,
  resourcePolicy,
  trustStatus,
  globalSeq

Auth(x, a) == x \in authPolicy[a]

AuthResource(x, r, a) ==
  /\ x \in authPolicy[a]
  /\ r \in resourcePolicy[a]

Trusted(a) == trustStatus[a] = "trusted"

Observe(e, x, uid, r) ==
  [entity |-> e, action |-> x, uid |-> uid,
   resource |-> r, seq |-> globalSeq]

Execute(e, x, uid, r) ==
  [entity |-> e, action |-> x, uid |-> uid,
   resource |-> r, seq |-> globalSeq]

Deny(x, uid, r) ==
  [action |-> x, uid |-> uid, resource |-> r,
   decision |-> "DENIED", seq |-> globalSeq]

Allow(x, uid, r) ==
  [action |-> x, uid |-> uid, resource |-> r,
   decision |-> "ALLOWED", seq |-> globalSeq]

SemanticallyCorrect(a) ==
  \A x \in Actions: (x \in authPolicy[a]) = intent[a][x]

IdentityBound(obs, enf) ==
  /\ obs.uid = enf.uid
  /\ obs.action = enf.action
  /\ obs.resource = enf.resource

ObsBeforeEnf(obs, enf) == obs.seq < enf.seq
ObsBeforeExec(obs, exe) == obs.seq < exe.seq
EnfBeforeExec(enf, exe) == enf.seq < exe.seq

=============================================================================
