"""The public API signature check must understand class methods."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

from axiomgate_kernel.execution import EffectExecutionResult

_CHECKER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "check_api_doc.py"
_CHECKER_SPEC = spec_from_file_location("axiomgate_test_check_api_doc", _CHECKER_PATH)
if _CHECKER_SPEC is None or _CHECKER_SPEC.loader is None:
    raise ImportError(f"cannot load API checker from {_CHECKER_PATH}")
check_api_doc = module_from_spec(_CHECKER_SPEC)
_CHECKER_SPEC.loader.exec_module(check_api_doc)


def test_signature_checker_resolves_documented_class_method():
    """Bare pytest omits the checkout root; load the helper by path before checking a classmethod."""
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
