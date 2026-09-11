"""Require the full suite to reject removal of every grant critical section."""

import ast
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_FAILURES = {
    "create_pending_context": {"test_create_pending_context_holds_store_lock"},
    "attach_owner_decision": {"test_attach_owner_decision_holds_store_lock"},
    "get_by_escalation": {
        "test_create_pending_context_holds_store_lock",
        "test_attach_owner_decision_holds_store_lock",
        "test_get_by_escalation_holds_store_lock",
    },
    "consume_if_valid": {
        "test_competing_consumers_have_one_winner",
        "test_rollback_and_redemption_share_the_critical_section[consume]",
        "test_rollback_and_redemption_share_the_critical_section[unconsume]",
    },
    "unconsume": {
        "test_rollback_and_redemption_share_the_critical_section[consume]",
        "test_rollback_and_redemption_share_the_critical_section[unconsume]",
    },
}


def main():
    source = (ROOT / "axiomgate_kernel" / "grant.py").read_text()
    baseline_cases = None
    for method in (None, *EXPECTED_FAILURES):
        with tempfile.TemporaryDirectory(prefix="axiomgate-grant-concurrency-") as tmp:
            copy = Path(tmp)
            for folder in ("axiomgate_kernel", "tests", "scripts", "examples"):
                shutil.copytree(ROOT / folder, copy / folder,
                                ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copy2(ROOT / "pyproject.toml", copy / "pyproject.toml")
            if method is not None:
                tree = ast.parse(source)
                store = next(n for n in tree.body
                             if isinstance(n, ast.ClassDef) and n.name == "ReservedGrantStore")
                function = next(n for n in store.body
                                if isinstance(n, ast.FunctionDef) and n.name == method)
                sections = [n for n in function.body if isinstance(n, ast.With)]
                if len(sections) != 1 or ast.unparse(sections[0].items[0].context_expr) != "self._lock":
                    raise RuntimeError(f"{method}: expected one grant lock to mutate")
                section = sections[0]
                index = function.body.index(section)
                function.body[index:index + 1] = section.body
                (copy / "axiomgate_kernel" / "grant.py").write_text(ast.unparse(tree) + "\n")
            report = copy / "suite.xml"
            run = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", f"--junitxml={report}"],
                cwd=copy, capture_output=True, text=True, timeout=90,
            )
            if not report.is_file():
                raise RuntimeError(f"{method}: no suite report\n{run.stdout}\n{run.stderr}")
            cases = list(ET.parse(report).iter("testcase"))
            failures = {c.attrib["name"] for c in cases if c.find("failure") is not None}
            errors = [c for c in cases if c.find("error") is not None]
            skipped = [c for c in cases if c.find("skipped") is not None]
            identities = sorted((c.attrib.get("classname"), c.attrib["name"]) for c in cases)
            if method is None:
                if run.returncode != 0 or not cases or failures or errors or skipped:
                    raise RuntimeError(f"isolated baseline is not green\n{run.stdout}\n{run.stderr}")
                baseline_cases = identities
                continue
            expected = EXPECTED_FAILURES[method]
            if (run.returncode != 1 or failures != expected
                    or errors or skipped or identities != baseline_cases):
                raise RuntimeError(f"{method}: unexpected mutation result\n{run.stdout}\n{run.stderr}")
            print(f"{method}: full suite rejected the missing lock at its scheduled interleaving")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
