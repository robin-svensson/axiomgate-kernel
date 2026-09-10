------------------------------- MODULE GovernanceMCV6 -------------------------------
EXTENDS GovernanceV6, GovernanceInvariantsV6, GovernanceTransitionsV6

Init ==
  /\ authPolicy = [a \in Authority |-> {}]
  /\ initPolicy = [a \in Authority |-> {}]
  /\ entityState = [e \in Entity |-> "idle"]
  /\ trustDomain = Authority
  /\ obsLog = <<>>
  /\ execLog = <<>>
  /\ enforceLog = <<>>
  /\ intent = [a \in Authority |-> [x \in Actions |-> FALSE]]
  /\ bootstrapDone = FALSE
  /\ uidCounter = 0
  /\ resourcePolicy = [a \in Authority |-> {}]
  /\ trustStatus = [a \in Authority |-> "trusted"]
  /\ globalSeq = 0

BoundedNext ==
  \/ \E a \in Authority, p \in SUBSET Actions, i \in [Actions -> BOOLEAN],
      rp \in SUBSET Resources:
      /\ \A x \in Actions: (x \in p) = i[x]
      /\ Bootstrap(a, p, i, rp, [a2 \in Authority |-> "trusted"])
  \/ \E e \in Entity, x \in Actions, r \in Resources:
      /\ uidCounter < 2
      /\ Len(obsLog) < 3
      /\ AttemptAction(e, x, r)
  \/ \E e \in Entity, x \in Actions, uid \in 0..uidCounter, r \in Resources:
      /\ Len(obsLog) < 3
      /\ ObserveAction(e, x, uid, r)
  \/ \E e \in Entity, x \in Actions, uid \in 0..uidCounter,
      r \in Resources, a \in Authority:
      /\ Len(enforceLog) < 3
      /\ EnforceAction(e, x, uid, r, a)
  \/ \E e \in Entity: ReturnToIdle(e)

Next == BoundedNext

TypeInvariant ==
  /\ authPolicy \in [Authority -> SUBSET Actions]
  /\ initPolicy \in [Authority -> SUBSET Actions]
  /\ entityState \in [Entity -> {"idle", "attempting", "executed", "denied"}]
  /\ trustDomain \subseteq Authority \cup Entity
  /\ obsLog \in Seq([entity: Entity, action: Actions, uid: Nat,
      resource: Resources, seq: Nat])
  /\ execLog \in Seq([entity: Entity, action: Actions, uid: Nat,
      resource: Resources, seq: Nat])
  /\ enforceLog \in Seq([action: Actions, uid: Nat, resource: Resources,
      decision: {"ALLOWED", "DENIED"}, seq: Nat])
  /\ intent \in [Authority -> [Actions -> BOOLEAN]]
  /\ bootstrapDone \in BOOLEAN
  /\ uidCounter \in Nat
  /\ resourcePolicy \in [Authority -> SUBSET Resources]
  /\ trustStatus \in [Authority -> {"trusted", "untrusted"}]
  /\ globalSeq \in Nat

===============================================================================
