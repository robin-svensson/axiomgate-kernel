------------------------------ MODULE GovernanceTransitionsV6 ------------------------------
EXTENDS GovernanceV6

Bootstrap(a, policy, newIntent, newResource, trustMap) ==
  /\ ~bootstrapDone
  /\ a \in Authority
  /\ \A x \in Actions: (x \in policy) = newIntent[x]
  /\ authPolicy' = [authPolicy EXCEPT ![a] = policy]
  /\ initPolicy' = [initPolicy EXCEPT ![a] = policy]
  /\ intent' = [intent EXCEPT ![a] = newIntent]
  /\ resourcePolicy' = [resourcePolicy EXCEPT ![a] = newResource]
  /\ trustStatus' = [trustStatus EXCEPT ![a] = trustMap[a]]
  /\ bootstrapDone' = TRUE
  /\ uidCounter' = uidCounter
  /\ globalSeq' = globalSeq
  /\ UNCHANGED <<entityState, trustDomain, obsLog, execLog, enforceLog>>

AttemptAction(e, x, r) ==
  /\ entityState[e] = "idle"
  /\ entityState' = [entityState EXCEPT ![e] = "attempting"]
  /\ uidCounter' = uidCounter + 1
  /\ UNCHANGED <<authPolicy, initPolicy, trustDomain, obsLog,
                  execLog, enforceLog, intent, bootstrapDone,
                  resourcePolicy, trustStatus, globalSeq>>

ObserveAction(e, x, uid, r) ==
  /\ entityState[e] = "attempting"
  /\ globalSeq' = globalSeq + 1
  /\ obsLog' = Append(obsLog, Observe(e, x, uid, r))
  /\ UNCHANGED <<authPolicy, initPolicy, entityState, trustDomain,
                  execLog, enforceLog, intent, bootstrapDone,
                  resourcePolicy, trustStatus, uidCounter>>

\* Enforcement and execution get DIFFERENT seq numbers
EnforceAction(e, x, uid, r, a) ==
  /\ entityState[e] = "attempting"
  /\ bootstrapDone
  /\ Trusted(a)
  /\ \E i \in 1..Len(obsLog):
      obsLog[i].uid = uid /\ obsLog[i].entity = e /\
      obsLog[i].action = x /\ obsLog[i].resource = r
  /\ IF AuthResource(x, r, a)
     THEN /\ enforceLog' = Append(enforceLog,
              [action |-> x, uid |-> uid, resource |-> r,
               decision |-> "ALLOWED", seq |-> globalSeq + 1])
          /\ execLog' = Append(execLog,
              [entity |-> e, action |-> x, uid |-> uid,
               resource |-> r, seq |-> globalSeq + 2])
          /\ entityState' = [entityState EXCEPT ![e] = "executed"]
          /\ globalSeq' = globalSeq + 2
     ELSE /\ enforceLog' = Append(enforceLog,
              [action |-> x, uid |-> uid, resource |-> r,
               decision |-> "DENIED", seq |-> globalSeq + 1])
          /\ entityState' = [entityState EXCEPT ![e] = "denied"]
          /\ globalSeq' = globalSeq + 1
          /\ UNCHANGED execLog
  /\ UNCHANGED <<authPolicy, initPolicy, trustDomain, obsLog,
                  intent, bootstrapDone, uidCounter,
                  resourcePolicy, trustStatus>>

ReturnToIdle(e) ==
  /\ entityState[e] \in {"executed", "denied"}
  /\ entityState' = [entityState EXCEPT ![e] = "idle"]
  /\ UNCHANGED <<authPolicy, initPolicy, trustDomain, obsLog,
                  execLog, enforceLog, intent, bootstrapDone,
                  uidCounter, resourcePolicy, trustStatus, globalSeq>>

=============================================================================
