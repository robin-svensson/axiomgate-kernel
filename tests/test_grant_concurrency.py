"""The atomicity claim previously had only sequential grant tests behind it."""

from queue import Queue
from threading import Event, Thread

import pytest

import axiomgate_kernel.grant as grant_module
from axiomgate_kernel.execution import ExecutionLog
from axiomgate_kernel.grant import GrantError, ReasonClass, ReservedGrantStore


WAIT = 5


def _ready(log):
    store = ReservedGrantStore(executions=log)
    args = dict(
        escalation_id="esc-thread", principal_id="p", agent_id="a",
        request_id="req-thread", action="read", domain="code", risk_level="low",
        payload_hash="payload", capability_id="cap", capability_scope_hash="scope",
        policy_hash="policy", provenance_identity="repo|branch|head",
    )
    store.create_pending_context(
        **args, policy_version="v1", provenance_kind="match",
        reason_class=ReasonClass.OTHER,
    )
    store.attach_owner_decision(args["escalation_id"], "permit")
    return store, args


def _start(call):
    result = Queue()

    def run():
        try:
            result.put((True, call()))
        except BaseException as exc:
            result.put((False, exc))

    # A broken lock must fail the suite, not leave pytest hanging at shutdown.
    thread = Thread(target=run, daemon=True)
    thread.start()
    return thread, result


def _finish(worker):
    thread, result = worker
    thread.join(WAIT)
    assert not thread.is_alive(), "grant worker did not finish"
    ok, value = result.get_nowait()
    if not ok:
        raise value
    return value


class _ObservedLock:
    """Signal actual contention on a real lock, without a scheduler sleep."""

    def __init__(self, lock):
        self.lock = lock
        self.contended = Event()

    def __enter__(self):
        if not self.lock.acquire(blocking=False):
            self.contended.set()
            self.lock.acquire()
        return self

    def __exit__(self, *exc):
        self.lock.release()


def test_competing_consumers_have_one_winner():
    """A split check/write could redeem one permit more than once.

    Pause the first state write after the consumed check. A missing store lock
    then lets the second consumer pass the same check before either write is
    visible; the real lock keeps it blocked until the first write completes.
    """
    log = ExecutionLog()
    store, args = _ready(log)
    gid = store._by_escalation[args["escalation_id"]]
    first_write, second_write, release = Event(), Event(), Event()
    original_items = store._items

    class _PausedItems(dict):
        writes = 0

        def __setitem__(self, key, value):
            if key == gid and value.consumed:
                self.writes += 1
                if self.writes == 1:
                    first_write.set()
                    assert release.wait(WAIT), "first consumer did not resume"
                else:
                    second_write.set()
            return super().__setitem__(key, value)

    store._items = _PausedItems(original_items)

    def consume():
        try:
            return store.consume_if_valid(**args)
        except GrantError as exc:
            assert str(exc) == "grant already consumed"
            return None

    workers = []
    try:
        workers.append(_start(consume))
        assert first_write.wait(WAIT), "first consumer did not reach the state write"
        workers.append(_start(consume))
        assert not second_write.wait(0.2), (
            "second consumer passed the consumed check before the first write"
        )
    finally:
        release.set()
        for thread, _ in workers:
            thread.join(WAIT)

    results = [_finish(worker) for worker in workers]
    winners = [result for result in results if result is not None]
    assert len(winners) == 1
    assert winners[0].consumed is True
    assert store.get_by_escalation(args["escalation_id"]) == winners[0]
    entries = log.entries()
    assert len(entries) == 1
    assert type(entries[0].seq) is int
    assert entries[0].rolled_back is False
    assert entries[0].request_id == args["request_id"]


def test_create_pending_context_holds_store_lock(monkeypatch):
    """Creating a grant must not overlap a concurrent lookup."""
    log = ExecutionLog()
    store, args = _ready(log)
    lock = _ObservedLock(store._lock)
    monkeypatch.setattr(store, "_lock", lock)
    entered, release = Event(), Event()
    original_now = grant_module._now

    def paused_now():
        entered.set()
        assert release.wait(WAIT), "create worker did not resume"
        return original_now()

    monkeypatch.setattr(grant_module, "_now", paused_now)
    new_args = {**args, "escalation_id": "esc-create"}
    workers = []
    try:
        workers.append(_start(lambda: store.create_pending_context(
            **new_args, policy_version="v1", provenance_kind="match",
            reason_class=ReasonClass.OTHER,
        )))
        assert entered.wait(WAIT), "create worker did not reach its critical section"
        workers.append(_start(lambda: store.get_by_escalation("esc-create")))
        assert lock.contended.wait(WAIT), "lookup bypassed the create lock"
    finally:
        release.set()
        for thread, _ in workers:
            thread.join(WAIT)

    _finish(workers[0])
    assert _finish(workers[1]) is not None


def test_attach_owner_decision_holds_store_lock():
    """Attaching the Owner decision must not overlap a concurrent lookup."""
    log = ExecutionLog()
    store, args = _ready(log)
    gid = store._by_escalation[args["escalation_id"]]
    lock = _ObservedLock(store._lock)
    store._lock = lock
    entered, release = Event(), Event()
    original_items = store._items

    class _PausedItems(dict):
        paused = False

        def __getitem__(self, key):
            if not self.paused and key == gid:
                self.paused = True
                entered.set()
                assert release.wait(WAIT), "attach worker did not resume"
            return super().__getitem__(key)

        def get(self, key, default=None):
            return super().get(key, default)

    store._items = _PausedItems(original_items)
    workers = []
    try:
        workers.append(_start(lambda: store.attach_owner_decision(
            args["escalation_id"], "permit"
        )))
        assert entered.wait(WAIT), "attach worker did not reach its critical section"
        workers.append(_start(lambda: store.get_by_escalation(args["escalation_id"])))
        assert lock.contended.wait(WAIT), "lookup bypassed the attach lock"
    finally:
        release.set()
        for thread, _ in workers:
            thread.join(WAIT)

    assert _finish(workers[0]).owner_decision == "permit"
    assert _finish(workers[1]).owner_decision == "permit"


def test_get_by_escalation_holds_store_lock():
    """A lookup must not overlap another lookup while reading the store."""
    log = ExecutionLog()
    store, args = _ready(log)
    gid = store._by_escalation[args["escalation_id"]]
    lock = _ObservedLock(store._lock)
    store._lock = lock
    entered, bypassed, release = Event(), Event(), Event()
    original_items = store._items

    class _PausedItems(dict):
        reads = 0

        def get(self, key, default=None):
            if key == gid:
                self.reads += 1
                if self.reads == 1:
                    entered.set()
                    assert release.wait(WAIT), "first lookup did not resume"
                else:
                    bypassed.set()
            return super().get(key, default)

    store._items = _PausedItems(original_items)
    workers = []
    try:
        workers.append(_start(lambda: store.get_by_escalation(args["escalation_id"])))
        assert entered.wait(WAIT), "first lookup did not reach its critical section"
        workers.append(_start(lambda: store.get_by_escalation(args["escalation_id"])))
        assert not bypassed.wait(0.2), "second lookup bypassed the store lock"
    finally:
        release.set()
        for thread, _ in workers:
            thread.join(WAIT)

    assert _finish(workers[0]) == _finish(workers[1])


@pytest.mark.parametrize("first", ["consume", "unconsume"])
def test_rollback_and_redemption_share_the_critical_section(monkeypatch, first):
    """Sequential rollback tests missed a window between state and log updates.

    If either method releases the lock before bookkeeping, rollback can miss
    the execution sequence or overlap the next redemption. Hold that window
    open and require the competing operation to block on the same real lock.
    """
    log = ExecutionLog()
    store, args = _ready(log)
    consume = lambda: store.consume_if_valid(**args)
    unconsume = lambda: store.unconsume(args["escalation_id"])
    if first == "unconsume":
        consume()

    lock = _ObservedLock(store._lock)
    monkeypatch.setattr(store, "_lock", lock)
    entered, release = Event(), Event()
    method = "record" if first == "consume" else "mark_rolled_back"
    original = getattr(log, method)
    waits = Queue()
    states = Queue()

    def paused(*a, **kw):
        # This hook runs inside the first worker's critical section. Inspect
        # the stored value here: the public getter would try to reacquire its
        # non-reentrant lock. In particular, unconsume has already restored
        # availability before mark_rolled_back; the next consumer must wait.
        states.put(store._items[store._by_escalation[args["escalation_id"]]].consumed)
        entered.set()
        # Store code deliberately swallows log exceptions. Carry timeout state
        # outside that handler so it cannot turn a failed schedule into a pass.
        waits.put(release.wait(WAIT))
        return original(*a, **kw)

    monkeypatch.setattr(log, method, paused)
    workers = []
    try:
        workers.append(_start(consume if first == "consume" else unconsume))
        assert entered.wait(WAIT), "first operation did not reach bookkeeping"
        workers.append(_start(unconsume if first == "consume" else consume))
        assert lock.contended.wait(WAIT), "second operation bypassed the grant lock"
        assert workers[1][1].empty(), "contender completed inside bookkeeping"
    finally:
        release.set()
        for thread, _ in workers:
            thread.join(WAIT)

    results = [_finish(worker) for worker in workers]
    assert waits.get_nowait() is True, "bookkeeping pause timed out"
    assert states.get_nowait() is (first == "consume")
    grant = store.get_by_escalation(args["escalation_id"])
    entries = log.entries()
    assert grant.consumed is (first == "unconsume")
    assert [entry.rolled_back for entry in entries] == (
        [True] if first == "consume" else [True, False]
    )
    assert [entry.seq for entry in entries] == list(range(1, len(entries) + 1))
    assert all(type(entry.seq) is int for entry in entries)
    assert all(entry.request_id == args["request_id"] for entry in entries)
    assert results[0 if first == "consume" else 1].consumed is True
    assert results[1 if first == "consume" else 0] is None
