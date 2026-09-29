"""The executor callback must not be replaceable after a Kernel permit."""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from threading import Lock
from uuid import uuid4

import pytest

from axiomgate_kernel import (
    ActionType,
    AuditLog,
    Authenticator,
    CapabilityRegistry,
    EffectExecutionContext,
    FixedProvenanceChecker,
    KernelEffectRunner,
    ExecutionError,
    EffectExecutionResult,
    EffectExecutorRegistry,
    EffectStatus,
    EffectGrantBinding,
    Mediator,
    PolicySnapshot,
    PrincipalKeyStore,
    ProductionEffectGrantStore,
    ProvisioningToken,
    RiskLevel,
    Role,
    Verdict,
    canonical_bytes,
    generate_key,
    make_capability,
    sha256_hex,
    sign_request,
)
from axiomgate_kernel.provenance import ProvenanceKind, ProvenanceResult


EXECUTOR_ID = "paid.test.write.v1"
EFFECT_CATEGORY = "test.write"
RESOURCE = "order:order-1"
OPERATION = "write"
DOMAIN = "paid_audit"


def _system(writer=None, output_digest=None, executor=None, audit_path="unused-injected-writer"):
    """Create a real mediator and a frozen registry for boundary tests."""
    owner_key = generate_key()
    agent_key = generate_key()
    token = ProvisioningToken()
    keys = PrincipalKeyStore()
    keys.register("owner", owner_key, token)
    keys.register("paid-worker", agent_key, token)
    keys.seal(token)

    registry = CapabilityRegistry()
    cap_token = ProvisioningToken()
    registry.register(
        make_capability(
            capability_id="cap-paid-worker",
            principal_id="paid-worker",
            role=Role.R_ENG,
            domains=[DOMAIN],
            action_types=[ActionType.EXECUTE],
            risk_ceiling=RiskLevel.MEDIUM,
            issued_by="Owner",
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        ),
        cap_token,
    )
    registry.seal(cap_token)

    audit = AuditLog(
        audit_path,
        generate_key(),
        writer=writer or (lambda _path, _line: None),
    )
    mediator = Mediator(
        authenticator=Authenticator(keys),
        registry=registry,
        audit=audit,
        provenance=FixedProvenanceChecker(
            ProvenanceResult(ProvenanceKind.MATCH, "test policy provenance")
        ),
        policy=PolicySnapshot.from_body("test-v1", {"rules": ["default"]}),
    )
    calls = []

    def execute(context, arguments_bytes, payload):
        arguments = json.loads(arguments_bytes)
        calls.append((arguments, payload))
        context.begin_effect()
        return EffectExecutionResult.success(
            value="written",
            provider_reference="receipt-1",
            idempotency_reference=arguments.get("idempotency_key"),
            output_digest=output_digest,
        )

    executors = EffectExecutorRegistry()
    executors.register(EXECUTOR_ID, executor or execute)
    executors.freeze()
    runner = KernelEffectRunner(
        mediator,
        audit,
        executors,
        ProductionEffectGrantStore(),
    )
    return runner, agent_key, calls, audit


def _request(key, arguments, payload, **overrides):
    args_digest = sha256_hex(canonical_bytes(arguments))
    body = {
        "principal_id": "paid-worker",
        "agent_id": "paid-worker",
        "action_type": "EXECUTE",
        "domain": DOMAIN,
        "risk_level": "MEDIUM",
        "tool_name": f"production_effect.{EFFECT_CATEGORY}",
        "effect_category": EFFECT_CATEGORY,
        "executor_id": EXECUTOR_ID,
        "resource": RESOURCE,
        "operation": OPERATION,
        "arguments_sha256": args_digest,
        "payload_sha256": sha256_hex(payload),
        "request_id": uuid4().hex,
        "nonce": uuid4().hex,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    body.update(overrides)
    return sign_request(body, key)


def _execute(runner, request, arguments, payload, **overrides):
    return runner.execute(
        request,
        executor_id=overrides.get("executor_id", EXECUTOR_ID),
        effect_category=overrides.get("effect_category", EFFECT_CATEGORY),
        resource=overrides.get("resource", RESOURCE),
        operation=overrides.get("operation", OPERATION),
        arguments=arguments,
        payload=payload,
    )


def test_permit_is_audited_before_locked_executor_and_outcome_after():
    """A decision without grant consumption and a fixed executor is not an effect boundary."""
    records = []
    lock = Lock()

    def writer(_path, line):
        with lock:
            records.append(json.loads(line))

    runner, key, calls, _audit = _system(writer)
    arguments = {"idempotency_key": "idem-1", "target": "object-1"}
    payload = b"artifact"
    outcome = _execute(runner, _request(key, arguments, payload), arguments, payload)

    assert outcome.status is EffectStatus.SUCCESS
    assert outcome.value == "written"
    assert outcome.provider_reference == "receipt-1"
    assert outcome.grant_id
    assert len(calls) == 1
    assert [row.get("event_type") for row in records[-2:]] == [
        "effect.grant_issued",
        "effect.completed",
    ]
    assert records[-2]["grant_id"] == outcome.grant_id
    assert records[-1]["decision_record_entry"] == outcome.authorization_audit_hash


def test_registered_executor_output_digest_is_recorded():
    """The effect record must bind the artifact identity produced by a locked executor."""
    records = []

    def writer(_path, line):
        records.append(json.loads(line))

    runner, key, _calls, _audit = _system(writer, output_digest="a" * 64)
    arguments = {"idempotency_key": "idem-2", "target": "object-2"}
    payload = b"source snapshot"
    outcome = _execute(runner, _request(key, arguments, payload), arguments, payload)

    assert outcome.status is EffectStatus.SUCCESS
    assert outcome.output_digest == "a" * 64
    assert records[-1]["output_sha256"] == "a" * 64


def test_denied_request_does_not_reach_registered_executor():
    """A valid signature outside the worker capability must still produce no effect."""
    runner, key, calls, _audit = _system()
    arguments = {"target": "object-1"}
    payload = b"artifact"
    request = _request(key, arguments, payload, domain="outside_scope")

    outcome = _execute(runner, request, arguments, payload)

    assert outcome.status is EffectStatus.DENIED
    assert calls == []


@pytest.mark.parametrize(
    ("field", "wrong"),
    [
        ("executor_id", "paid.test.other.v1"),
        ("effect_category", "test.delete"),
        ("resource", "order:order-2"),
        ("operation", "delete"),
    ],
)
def test_runtime_binding_mismatch_fails_before_executor(field, wrong):
    """The runtime invocation must equal the fields the signed request authorized."""
    runner, key, calls, _audit = _system()
    arguments = {"target": "object-1"}
    payload = b"artifact"
    request = _request(key, arguments, payload)

    outcome = _execute(runner, request, arguments, payload, **{field: wrong})

    assert outcome.status is EffectStatus.DENIED
    assert calls == []


def test_argument_or_payload_digest_mismatch_fails_before_executor():
    """A permit for one canonical argument or artifact must not authorize another."""
    runner, key, calls, _audit = _system()
    authorized_arguments = {"target": "object-1"}
    authorized_payload = b"artifact-a"
    request = _request(key, authorized_arguments, authorized_payload)

    outcome = _execute(
        runner,
        request,
        {"target": "object-2"},
        b"artifact-b",
    )

    assert outcome.status is EffectStatus.DENIED
    assert calls == []


def test_execute_has_no_callback_parameter_and_frozen_registry_rejects_substitution():
    """A post-authorization callback would let a caller replace the approved effect."""
    import inspect

    runner, _key, _calls, _audit = _system()
    assert "executor" not in inspect.signature(runner.execute).parameters
    with pytest.raises(TypeError):
        runner.execute({}, executor=lambda *_args: None)

    registry = EffectExecutorRegistry()
    registry.register("test.fixed.v1", lambda *_args: None)
    registry.freeze()
    with pytest.raises(Exception, match="frozen"):
        registry.register("test.late.v1", lambda *_args: None)


def test_executor_context_is_runner_issued_and_bound_to_executor():
    """A copied executor cannot be invoked directly with a caller-built context."""
    with pytest.raises(ExecutionError):
        EffectExecutionContext("grant", EXECUTOR_ID, "request")

    seen = []

    def executor(context, _arguments_bytes, _payload):
        context.require_executor(EXECUTOR_ID)
        seen.append(context)
        context.begin_effect()
        return EffectExecutionResult.success(value="written")

    runner, key, _calls, _audit = _system(executor=executor)
    arguments = {"target": "object-context"}
    payload = b"artifact"
    outcome = _execute(runner, _request(key, arguments, payload), arguments, payload)

    assert outcome.status is EffectStatus.SUCCESS
    assert seen[0].grant_id == outcome.grant_id
    assert seen[0].request_id == outcome.request_id
    with pytest.raises(ExecutionError):
        seen[0].require_executor("paid.test.other.v1")


def test_production_grant_is_bound_single_use_and_replay_rejected():
    """A consumed permit must not be redeemable a second time or for another binding."""
    runner, key, _calls, _audit = _system()
    arguments = {"target": "object-1"}
    payload = b"artifact"
    request = _request(key, arguments, payload)
    outcome = _execute(runner, request, arguments, payload)

    assert outcome.status is EffectStatus.SUCCESS
    with pytest.raises(Exception, match="already consumed"):
        runner._grant_store.consume(
            outcome.grant_id,
            EffectGrantBinding(
                request_id=request["request_id"],
                principal_id="paid-worker",
                action="EXECUTE",
                tool=f"production_effect.{EFFECT_CATEGORY}",
                effect_category=EFFECT_CATEGORY,
                resource=RESOURCE,
                operation=OPERATION,
                arguments_digest=sha256_hex(canonical_bytes(arguments)),
                payload_digest=sha256_hex(payload),
                executor_id=EXECUTOR_ID,
            ),
        )


def test_pre_effect_audit_failure_never_invokes_executor():
    """If a permit or grant record cannot be persisted, no external effect may run."""
    def broken_writer(_path, _line):
        raise OSError("disk full")

    runner, key, calls, _audit = _system(broken_writer)
    arguments = {"target": "object-1"}
    payload = b"artifact"
    outcome = _execute(runner, _request(key, arguments, payload), arguments, payload)

    assert outcome.status is EffectStatus.DENIED
    assert calls == []


def test_post_effect_audit_failure_is_indeterminate_and_not_success():
    """A successful provider effect without durable closure is not a verified success."""
    records = []

    def fail_post_effect(_path, line):
        record = json.loads(line)
        if record.get("event_type") == "effect.completed":
            raise OSError("disk full after effect")
        records.append(record)

    runner, key, calls, _audit = _system(fail_post_effect)
    arguments = {"target": "object-1"}
    payload = b"artifact"
    outcome = _execute(runner, _request(key, arguments, payload), arguments, payload)

    assert outcome.status is EffectStatus.INDETERMINATE_AFTER_EFFECT
    assert outcome.value is None
    assert calls


def test_retry_mints_a_new_grant_and_keeps_provider_idempotency_reference():
    """A retry may reuse provider idempotency, never a consumed Kernel grant."""
    runner, key, calls, _audit = _system()
    arguments = {"idempotency_key": "session-idem-1", "target": "object-1"}
    payload = b"artifact"

    first = _execute(runner, _request(key, arguments, payload), arguments, payload)
    second = _execute(runner, _request(key, arguments, payload), arguments, payload)

    assert first.status is second.status is EffectStatus.SUCCESS
    assert first.grant_id != second.grant_id
    assert first.idempotency_reference == second.idempotency_reference == "session-idem-1"
    assert len(calls) == 2


def test_async_executor_cancellation_after_effect_is_audited_as_indeterminate(tmp_path):
    """Cancellation during provider I/O cannot escape without a durable uncertain outcome."""
    async def exercise_cancellation():
        started = asyncio.Event()

        async def cancelled_executor(context, _arguments_bytes, _payload):
            context.begin_effect()
            started.set()
            await asyncio.Future()

        audit_path = tmp_path / "cancelled-effect.jsonl"

        def persist_audit(path, line):
            with open(path, "a", encoding="utf-8") as handle:
                handle.write(line)

        runner, key, _calls, audit = _system(
            writer=persist_audit,
            executor=cancelled_executor,
            audit_path=str(audit_path),
        )
        arguments = {"target": "object-cancelled"}
        payload = b"artifact"
        task = asyncio.create_task(runner.execute_async(
            _request(key, arguments, payload),
            executor_id=EXECUTOR_ID,
            effect_category=EFFECT_CATEGORY,
            resource=RESOURCE,
            operation=OPERATION,
            arguments=arguments,
            payload=payload,
        ))
        await started.wait()
        task.cancel()
        outcome = await task

        assert outcome.status is EffectStatus.INDETERMINATE_AFTER_EFFECT
        assert outcome.reason_code == "executor_cancelled"
        assert audit.entries()[-1]["outcome"] == "INDETERMINATE_AFTER_EFFECT"

    asyncio.run(exercise_cancellation())


def test_audit_reference_verification_is_read_only_on_malformed_tail(tmp_path):
    """A consumer must not repair the evidence while checking an effect reference."""
    from axiomgate_kernel import generate_key

    path = tmp_path / "effects.jsonl"
    key = generate_key()
    log = AuditLog(str(path), key)
    log.append({"event_type": "effect.completed", "executor_id": EXECUTOR_ID})
    with path.open("ab") as handle:
        handle.write(b"{broken-tail")
    before = path.read_bytes()

    valid, _message, _head, _count = AuditLog.verify_file(str(path), key)

    assert not valid
    assert path.read_bytes() == before
