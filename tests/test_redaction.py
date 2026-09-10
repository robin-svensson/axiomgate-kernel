"""Redaction at the audit write point.

Bug this file exists for (found by independent review 2026-09-10): redaction
matched credential *formats* only. A field literally named `password`, holding
a free-form value, was written to the append-only audit log in clear text. The
log is HMAC-chained, so the leak could not be edited out afterwards without
breaking the very chain the product sells.
"""
import os
import tempfile

import pytest

from axiomgate_kernel.audit import AuditLog
from axiomgate_kernel.redaction import redact_dict, redact_secrets

SENSITIVE_NAMES = [
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "authorization", "credential", "private_key", "access_token",
]


@pytest.mark.parametrize("name", SENSITIVE_NAMES)
def test_value_masked_by_field_name_regardless_of_shape(name):
    """A free-form value under a sensitive key must never survive."""
    out = redact_dict({name: "hunter2-plain-text"})
    assert "hunter2-plain-text" not in str(out), f"{name} leaked"


@pytest.mark.parametrize("name", ["PASSWORD", "Db_Secret", "user-api-key", "authToken"])
def test_field_name_match_is_case_and_separator_insensitive(name):
    out = redact_dict({name: "hunter2-plain-text"})
    assert "hunter2-plain-text" not in str(out), f"{name} leaked"


def test_nested_and_listed_values_are_masked():
    out = redact_dict({"outer": [{"db": {"password": "hunter2-plain-text"}}]})
    assert "hunter2-plain-text" not in str(out)


def test_benign_fields_are_left_alone():
    """Masking everything would destroy the audit value of the log."""
    out = redact_dict({"principal_id": "agent-a", "action": "EXECUTE", "count": 3})
    assert out == {"principal_id": "agent-a", "action": "EXECUTE", "count": 3}


def test_non_string_secret_value_is_still_removed():
    """A sensitive key holding an int or a list must not pass through either."""
    out = redact_dict({"api_key": 1234567890, "token": ["a", "b"]})
    assert "1234567890" not in str(out)
    assert "'a'" not in str(out)


def test_format_matching_still_works():
    """The original behaviour must survive: values that look like keys are masked."""
    assert "sk-" + "A" * 30 not in redact_secrets("key is sk-" + "A" * 30)


def test_audit_log_does_not_persist_named_secret():
    """The end-to-end property. This is what the README promises."""
    d = tempfile.mkdtemp()
    path = os.path.join(d, "audit.log")
    log = AuditLog(path, b"0" * 32)
    log.append({"password": "hunter2-plain-text", "key": "sk-" + "A" * 30})
    raw = open(path).read()
    assert "hunter2-plain-text" not in raw
    assert "sk-" + "A" * 30 not in raw
    ok, msg, _ = log.verify_chain()
    assert ok, msg


def test_redaction_happens_before_hashing():
    """Two logs differing only in a redacted value must hash identically."""
    d = tempfile.mkdtemp()
    a = AuditLog(os.path.join(d, "a.log"), b"0" * 32)
    b = AuditLog(os.path.join(d, "b.log"), b"0" * 32)
    ha = a.append({"request_id": "r1", "password": "first-plain-secret"})
    hb = b.append({"request_id": "r1", "password": "second-plain-secret"})
    assert ha == hb
