"""The public API signature check must understand class methods."""

from axiomgate_kernel.execution import EffectExecutionResult
from scripts import check_api_doc


def test_signature_checker_resolves_documented_class_method():
    """A valid documented classmethod must not appear missing from the API."""
    resolved, problem = check_api_doc.resolve(".success", EffectExecutionResult)

    assert problem is None
    assert resolved is not None
    assert check_api_doc.actual_params(resolved) == [
        "*",
        "value",
        "provider_reference",
        "idempotency_reference",
        "output_digest",
    ]
