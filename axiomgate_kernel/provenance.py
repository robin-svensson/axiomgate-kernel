"""AxiomGate Kernel — Provenance Verification

Repository/branch provenance. Unknown/unavailable never MATCH.
"""

from dataclasses import dataclass
from typing import Optional
import os
import subprocess


class ProvenanceKind:
    MATCH = "match"
    MISMATCH = "mismatch"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class ProvenanceResult:
    """Result of a provenance check."""
    kind: str
    reason: str
    actual_repo: Optional[str] = None
    actual_branch: Optional[str] = None
    head: Optional[str] = None
    declared_head: Optional[str] = None
    head_drift: bool = False

    @property
    def ok(self) -> bool:
        return self.kind == ProvenanceKind.MATCH

    @property
    def identity(self) -> str:
        return f"{self.actual_repo}|{self.actual_branch}|{self.head}"


class ProvenanceChecker:
    """Abstract base for provenance checkers."""
    def check(self) -> ProvenanceResult:
        raise NotImplementedError


class FixedProvenanceChecker(ProvenanceChecker):
    """Fixed provenance result. For testing only."""
    def __init__(self, result: ProvenanceResult) -> None:
        self._result = result

    def check(self) -> ProvenanceResult:
        return self._result


class GitProvenanceChecker(ProvenanceChecker):
    """Git-based provenance verification."""
    def __init__(
        self,
        expected_repo: str,
        expected_branch: str,
        declared_head: Optional[str] = None,
        git_binary: Optional[str] = None,
    ) -> None:
        self.expected_repo = expected_repo
        self.expected_branch = expected_branch
        self.declared_head = declared_head
        # Fail closed without an explicit absolute binary path
        if git_binary and not os.path.isabs(git_binary):
            self._git = None
        else:
            self._git = git_binary

    def check(self) -> ProvenanceResult:
        if not self._git or not os.path.isfile(self._git):
            return ProvenanceResult(ProvenanceKind.UNAVAILABLE, "git binary unavailable")
        env = os.environ.copy()
        for blocked in (
            "PYTHONPATH", "PYTHONHOME", "GIT_DIR", "GIT_WORK_TREE",
            "GIT_CONFIG", "GIT_EXEC_PATH", "GIT_TEMPLATE_DIR",
            "GIT_SSL_NO_VERIFY", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        ):
            env.pop(blocked, None)
        try:
            repo = subprocess.run(
                [self._git, "rev-parse", "--show-toplevel"],
                capture_output=True, text=True, timeout=5, env=env, stdin=subprocess.DEVNULL,
            )
            branch = subprocess.run(
                [self._git, "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True, text=True, timeout=5, env=env, stdin=subprocess.DEVNULL,
            )
            head = subprocess.run(
                [self._git, "rev-parse", "HEAD"],
                capture_output=True, text=True, timeout=5, env=env, stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return ProvenanceResult(ProvenanceKind.UNAVAILABLE, f"git unavailable: {exc}")

        if repo.returncode != 0 or branch.returncode != 0 or head.returncode != 0:
            return ProvenanceResult(ProvenanceKind.UNAVAILABLE, "git provenance unavailable")

        actual_repo = repo.stdout.strip()
        actual_branch = branch.stdout.strip()
        actual_head = head.stdout.strip()
        if not actual_repo or not actual_branch or not actual_head:
            return ProvenanceResult(ProvenanceKind.UNAVAILABLE, "git provenance empty")

        if os.path.normpath(actual_repo) != os.path.normpath(self.expected_repo):
            return ProvenanceResult(
                ProvenanceKind.MISMATCH,
                f"repository mismatch: {actual_repo} != {self.expected_repo}",
                actual_repo=actual_repo, actual_branch=actual_branch, head=actual_head,
                declared_head=self.declared_head,
            )
        if actual_branch != self.expected_branch:
            return ProvenanceResult(
                ProvenanceKind.MISMATCH,
                f"branch mismatch: {actual_branch} != {self.expected_branch}",
                actual_repo=actual_repo, actual_branch=actual_branch, head=actual_head,
                declared_head=self.declared_head,
            )
        drift = False
        if self.declared_head and not actual_head.startswith(self.declared_head):
            drift = True
        return ProvenanceResult(
            ProvenanceKind.MATCH, "provenance ok",
            actual_repo=actual_repo, actual_branch=actual_branch, head=actual_head,
            declared_head=self.declared_head, head_drift=drift,
        )
