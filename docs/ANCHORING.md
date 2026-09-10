# Integration note: anchoring the audit chain

**Status of this document.** It closes the documentation half of
[ROADMAP.md](ROADMAP.md) item **R2**. It does not close R2 itself — where an anchor is
stored is a deployment decision, and the kernel cannot make it.

Every command and every message quoted here was read back from a real run
(`scripts/anchor_probe.py`), not transcribed from the source.

---

## The property, stated exactly

`AuditLog` chains each entry to the previous one by hash and MACs the result, and each
entry carries its own position (`seq`) *inside* the hashed body. That makes an edit, an
insertion, a deletion and a renumbering all detectable by the log alone:

```python
ok, msg, last_hash = log.verify_chain()      # no anchor
```

**It does not make a truncation detectable.** A chain cut short still verifies:

```
kapad, ingen anchor -> (True, 'ok', '072eacf1…')
```

Two entries were removed from the end of a four-entry log and `verify_chain()` returned
`ok`. Every entry that remains does link correctly to the one before it. A
self-certifying log cannot prove its own length; this is why Certificate Transparency
signs tree heads rather than trusting a log to describe itself.

The anchor is the missing half:

```python
head_hash, count = log.head()     # store this outside the log

ok, msg, last = log.verify_chain(head_hash, count)
```

Against the same truncated log:

```
kapad, med anchor -> (False, 'log truncated: 2 entries, anchor expected 4')
```

---

## Store both halves, and store them where the writer cannot reach

`head()` returns `(last_entry_hash, entry_count)`. Both are needed, and they fail
differently:

| Anchor passed | Result on the truncated log |
|---|---|
| `verify_chain(head, count)` | `log truncated: 2 entries, anchor expected 4` |
| `verify_chain(None, count)` | `log truncated: 2 entries, anchor expected 4` |
| `verify_chain(head, None)` | `head mismatch: log does not end at the anchored entry` |

The count catches a shortened log. The head catches a log that has the right *length*
but does not end where it should — a tail rewritten with fabricated entries, which the
count alone would accept.

**Where.** The anchor has to live somewhere the process writing the log cannot modify:
another host, an append-only store under different credentials, a signed message to an
external service, a printed record. An anchor in a file next to `audit.log` proves
nothing, because whoever truncated one can rewrite the other.

---

## Cadence: the interval *is* the exposure window

Entries written after the most recent anchor are not covered by it. If you anchor
hourly, an hour of decisions can be removed and the check will still pass — the log
simply looks like it did at the last anchor.

So the cadence is a risk decision, not a performance one: **how much of the record are
you willing to be unable to prove existed?** Anchoring per decision closes the window
entirely and costs one external write per decision. Anchoring per batch trades that
window for throughput.

There is no correct default, so the kernel ships none. `head()` is cheap — it returns
in-memory state under the log's own lock and does not re-read the file — so a per-decision
anchor is affordable; what it costs is the external write.

---

## Anchoring a log that is still being written

**An anchor cannot be verified against a log that has grown since — not by the exact check.**

```
stale anchor -> (False, 'log longer than anchor: 4 entries, anchor expected 3')
```

That is a correct refusal, not a bug: `verify_chain` answers "is this log exactly the one
I anchored?", and for a log that is still being appended to the honest answer is no. The
question you usually want is the weaker one, and it has its own method:

```
stale anchor, prefix -> (True, 'prefix ok: 3 anchored entries verified, 1 appended since')
```

`verify_prefix(head, count)` asks "does this log begin with the chain I anchored, and
continue correctly from it?" It verifies every link in the file, then compares the hash
at the anchored position against the anchored head. So the two methods answer different
questions and neither replaces the other:

| Question | Method | On a living log |
|---|---|---|
| Is this exactly the log I anchored? | `verify_chain(head, count)` | fails, correctly |
| Does this log extend the log I anchored? | `verify_prefix(head, count)` | passes |

What the weaker question still catches:

```
kapad, prefix -> (False, 'log truncated: 2 entries, anchor expected at least 4')
utbytt kedja, prefix -> (False, 'prefix mismatch: the entry at the anchored position is not the anchored entry -- the log was replaced, not appended to')
```

The first is a removal: fewer entries than the anchor covers. The second is the case the
count alone would accept — a competing chain of the same length, internally valid,
written with the same key by whoever holds it. The anchored hash is what separates them,
which is why the anchor has to be *both* halves:

```
halvt anchor, prefix -> (False, 'prefix verification needs both halves of the anchor (head and count from a single head() call)')
```

```
noll count med head, prefix -> (False, 'invalid anchor: anchor_count is 0 but anchor_head is set -- there is no entry at position zero for that hash to be')
```

A count without a head proves only length; a head without a count has no position to
compare at; a count that is negative, or zero while a head is set, is not an anchor at
all but a bad call, and is refused as one — an argument error must not read as a finding. `verify_prefix` refuses the half-anchor rather than reporting on the part it
can check, because a partial answer here reads as a pass.

**What prefix verification does not give you.** Entries appended after the anchor are
still unanchored — the section on cadence above is unchanged. Prefix verification removes
the requirement to quiesce the writer; it does not extend the anchor's coverage forward.

---

## Verifying at startup

`AuditLog(path, key, anchor=(head, count))` runs the prefix check as part of construction
and refuses to open a log that fails it:

```
ankrad konstruktor pa kapad logg -> AuditError: audit log does not match its anchor: log truncated: 2 entries, anchor expected at least 4
ankrad konstruktor pa vaxt logg -> oppnade, 4 poster
```

The check runs *after* the replay, never before. If the last line of the file is a
partial write — the process died mid-append — the replay drops it, and if that line was
inside the anchored prefix the anchor check then fails. That ordering is deliberate: a
truncated tail is a recovery, but a truncated tail that swallowed an anchored entry is a
finding, and the anchor is what tells them apart.

Without `anchor=`, construction behaves as it always did: it replays the file, raises
`AuditError` if the chain is internally broken, and opens a truncated file without
complaint, because a truncated file is internally consistent. Passing the anchor is the
integrator's call, and the kernel defaults to the weaker behavior so that an existing
deployment does not start failing on an anchor it never had.

---

## Two things the kernel will still not do for you

1. **The kernel does not emit the anchor.** `head()` returns it; getting it to somewhere
   the writing process cannot reach — another host, an append-only store under different
   credentials, a signed message, a printed record — is deployment, not library code. An
   anchor in a file next to `audit.log` proves nothing, because whoever truncated one can
   rewrite the other.
2. **A pre-sequence log cannot be anchored at all.** A file written before `seq` was part
   of the hashed body fails with `legacy chain format`, deliberately distinct from
   `seq mismatch`: it is a format change, not tampering. It cannot be migrated in place —
   renumbering the entries would change the hashes that are the evidence. Archive the
   file as a sealed record and start a new chain.
