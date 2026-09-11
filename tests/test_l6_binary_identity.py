"""Regression cases for reviewer identity failures; no reviewer is executed."""
import hashlib
import os
import re
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

CHECKER = Path(__file__).resolve().parents[1] / "scripts/l6_binary_identity.py"


class BinaryIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.file = Path(self.temp.name) / "reviewer"
        self.file.write_bytes(b"\x7fELF-original-fixture")
        self.file.chmod(0o700)
        self.pin = hashlib.sha256(self.file.read_bytes()).hexdigest()

    def run_check(self, path=None, pin=None, approved=None):
        args = [sys.executable, str(CHECKER), "file", str(path or self.file), pin or self.pin]
        if approved is not None:
            args.append(approved)
        return subprocess.run(args, capture_output=True, text=True, check=False)

    def test_changed_bytes_exit_three_without_claiming_legitimate_update(self):
        """A modified executable must block, not be relabeled as a harmless old pin."""
        self.file.write_bytes(b"\x7fELF-replacement-fixture")
        result = self.run_check()
        self.assertEqual(result.returncode, 3)
        self.assertIn("PIN_CONTENT_CHANGED_UNVERIFIED", result.stderr)
        self.assertNotIn("PIN_STALE", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_reviewed_replacement_is_distinguished_but_still_blocks(self):
        """An approved update used to look identical to an unexplained replacement."""
        self.file.write_bytes(b"\x7fELF-approved-update-fixture")
        approved = hashlib.sha256(self.file.read_bytes()).hexdigest()
        result = self.run_check(approved=approved)
        self.assertEqual(result.returncode, 3)
        self.assertIn("PIN_STALE_APPROVED_UPDATE", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_nonmatching_update_record_does_not_explain_changed_bytes(self):
        """An update record for different bytes must not bless an unknown replacement."""
        self.file.write_bytes(b"\x7fELF-unexpected-fixture")
        result = self.run_check(approved="1" * 64)
        self.assertEqual(result.returncode, 3)
        self.assertIn("PIN_CONTENT_CHANGED_UNVERIFIED", result.stderr)
        self.assertNotIn("PIN_STALE", result.stderr)

    def test_exact_pin_accepts_observed_bytes(self):
        """Unconditional blocking would make the mismatch regression meaningless."""
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_pinned_path_has_separate_diagnostic(self):
        """A removed version must not be reported as a measured content mismatch."""
        self.file.unlink()
        result = self.run_check()
        self.assertEqual(result.returncode, 3)
        self.assertIn("PIN_TARGET_MISSING", result.stderr)

    def test_symlink_is_not_accepted_even_when_bytes_match(self):
        """A movable symlink would restore the routing ambiguity despite a matching hash."""
        link = self.file.with_name("link")
        link.symlink_to(self.file)
        result = self.run_check(path=link)
        self.assertEqual(result.returncode, 3)


    def test_latest_directory_resolves_but_leaf_symlink_stays_forbidden(self):
        """A valid executable beneath mise/latest was rejected solely for its parent link."""
        version = self.file.parent / "1.0"
        version.mkdir()
        executable = version / "reviewer"
        self.file.rename(executable)
        latest = self.file.parent / "latest"
        latest.symlink_to(version, target_is_directory=True)
        result = self.run_check(path=latest / "reviewer")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(executable), result.stdout)

    def test_dangerous_modes_block_unchanged_bytes(self):
        """Unchanged bytes could pass after becoming privileged or writable by another user."""
        for mode in (0o4755, 0o2755, 0o775, 0o757):
            with self.subTest(mode=oct(mode)):
                self.file.chmod(mode)
                result = self.run_check()
                self.assertEqual(result.returncode, 3)
                self.assertIn("PIN_UNSAFE_PERMISSIONS", result.stderr)

    def tree_check(self, root, pin, approved=None):
        args = [sys.executable, str(CHECKER), "tree", str(root), pin]
        if approved is not None:
            args.append(approved)
        return subprocess.run(args, capture_output=True, text=True, check=False)

    def tree_fixture(self):
        root = self.file.parent / "package"
        root.mkdir()
        (root / "b").write_bytes(b"two")
        (root / "a").write_bytes(b"one")
        # Fixed expected digest framing; independent of the checker implementation.
        framed = b"".join(len(n).to_bytes(8, "big") + n + hashlib.sha256(v).digest()
                          for n, v in [(b"a", b"one"), (b"b", b"two")])
        return root, hashlib.sha256(framed).hexdigest()

    def test_tree_hash_uses_stable_name_order(self):
        """Package identity had no regression for insertion-order-independent hashing."""
        root, pin = self.tree_fixture()
        self.assertEqual(self.tree_check(root, pin).returncode, 0)
        (root / "a").unlink()
        (root / "a").write_bytes(b"one")
        self.assertEqual(self.tree_check(root, pin).returncode, 0)

    def test_tree_mutations_exit_three(self):
        """Gemini package additions, removals and replacements had no subprocess coverage."""
        for change in ("content", "add", "remove"):
            with self.subTest(change=change):
                root, pin = self.tree_fixture()
                if change == "content":
                    (root / "a").write_bytes(b"changed")
                elif change == "add":
                    (root / "new").write_bytes(b"new")
                else:
                    (root / "a").unlink()
                result = self.tree_check(root, pin)
                self.assertEqual(result.returncode, 3)
                self.assertIn("PIN_CONTENT_CHANGED_UNVERIFIED", result.stderr)
                shutil.rmtree(root)

    def test_tree_rejects_links_special_files_and_empty_packages(self):
        """The package boundary could regress silently for unsupported filesystem entries."""
        for change in ("link", "fifo", "empty"):
            with self.subTest(change=change):
                root, pin = self.tree_fixture()
                if change == "link":
                    (root / "link").symlink_to(self.file)
                elif change == "fifo":
                    os.mkfifo(root / "fifo")
                else:
                    (root / "a").unlink()
                    (root / "b").unlink()
                self.assertEqual(self.tree_check(root, pin).returncode, 3)
                shutil.rmtree(root)

    def test_tree_unsafe_permissions_block_even_with_matching_content(self):
        """Package permissions were outside all checks despite affecting replacement risk."""
        root, pin = self.tree_fixture()
        (root / "a").chmod(0o666)
        result = self.tree_check(root, pin)
        self.assertEqual(result.returncode, 3)
        self.assertIn("PIN_UNSAFE_PERMISSIONS", result.stderr)

    def test_tree_approved_update_still_exits_three(self):
        """A known package update must not bypass promotion of its reviewed active pin."""
        root, pin = self.tree_fixture()
        result = self.tree_check(root, "0" * 64, approved=pin)
        self.assertEqual(result.returncode, 3)
        self.assertIn("PIN_STALE_APPROVED_UPDATE", result.stderr)


class GateWiringTests(unittest.TestCase):
    """Run an isolated script copy; all reviewer launch points are replaced by sentinels."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "scripts").mkdir()
        (self.root / "bin").mkdir()
        self.script = self.root / "scripts/l6-review.sh"
        self.source = CHECKER.with_name("l6-review.sh").read_text()
        # Replace every model call and replace timeout itself as defense in depth.
        self.source = self.source.replace("timeout 600 ", "reviewer_sentinel ")
        self.source = self.source.replace("set -uo pipefail", "set -uo pipefail\n"
            "reviewer_sentinel() { echo MODEL_SENTINEL_REACHED >&2; return 99; }")
        shutil.copyfile(CHECKER, self.root / "scripts/l6_binary_identity.py")
        (self.root / "scripts/verify_claims.sh").write_text("exit 0\n")
        git = self.root / "bin/git"
        git.write_text("#!/bin/sh\nif [ \"$1\" = diff ]; then echo fixture-diff; fi\n")
        git.chmod(0o755)
        timeout = self.root / "bin/timeout"
        timeout.write_text("#!/bin/sh\necho UNEXPECTED_TIMEOUT >&2; exit 99\n")
        timeout.chmod(0o755)
        self.env = {**os.environ, "PATH": str(self.root / "bin") + ":/usr/bin:/bin",
                    "L6_AUTHOR_VENDOR": "openai", "AXIOMGATE_KERNEL_PYTHON": "/usr/bin/true",
                    "AXIOMGATE_SCRATCH": str(self.root / "scratch")}
        for key in ("CI", "AGY_BIN", "GEMINI_CLI_BIN", "JENKINS_URL", "L6_ALLOW_SELF_REVIEW"):
            self.env.pop(key, None)

    def run_script(self, source=None, env=None):
        self.script.write_text(source if source is not None else self.source)
        return subprocess.run(["/usr/bin/bash", str(self.script)], env=env or self.env,
                              capture_output=True, text=True, check=False, timeout=10)

    def test_selected_hash_mismatch_exits_three_before_model(self):
        """Only testing the Python helper left the shell's fatal mismatch wiring unproven."""
        executable = self.root / "wrong-agy"
        executable.write_bytes(b"\x7fELF-wrong-bytes")
        executable.chmod(0o755)
        source = re.sub(r'^AGY=".*"$', 'AGY="' + str(executable) + '"', self.source, flags=re.M)
        result = self.run_script(source)
        self.assertEqual(result.returncode, 3)
        self.assertIn("PIN_CONTENT_CHANGED_UNVERIFIED", result.stderr)
        self.assertNotIn("MODEL_SENTINEL_REACHED", result.stderr)

    def test_skipped_codex_is_not_checked_before_selected_google_reviewer(self):
        """An unused author's own-vendor fallback could block every independent reviewer."""
        # The real verifier runs on a deliberately missing Codex path. Other
        # routes stop at a sentinel so no real executable can ever be launched.
        start = self.source.index('check_binary() {')
        end = self.source.index('\n}', start) + 2
        original = self.source[start:end].replace('check_binary()', 'original_check_binary()', 1)
        wrapper = original + '\ncheck_binary() { if [ "$1" = codex ]; then original_check_binary "$1"; else return 0; fi; }'
        source = self.source[:start] + wrapper + self.source[end:]
        source = re.sub(r'^CODEX_CLI=".*"$', 'CODEX_CLI="' + str(self.root / "missing-codex") + '"', source, flags=re.M)
        # Reach the first chosen route, then stop inside the shell (not a model).
        source = source.replace('OUT="$( cd "$EMPTY"', 'exit 42\n  OUT="$( cd "$EMPTY"', 1)
        result = self.run_script(source)
        self.assertEqual(result.returncode, 42, result.stderr)
        self.assertNotIn("PIN_TARGET_MISSING", result.stderr)

    def test_explicit_ci_is_blocked(self):
        """The local-only guard needs a measured shell exit, not just a comment."""
        result = self.run_script(env={**self.env, "CI": "true"})
        self.assertEqual(result.returncode, 3)
        self.assertIn("LOCAL_ONLY_CI", result.stderr)

    def test_jenkins_marker_is_blocked_without_generic_ci(self):
        """Jenkins can identify CI without setting the generic CI variable."""
        result = self.run_script(env={**self.env, "JENKINS_URL": "https://ci.invalid/"})
        self.assertEqual(result.returncode, 3)
        self.assertIn("LOCAL_ONLY_CI", result.stderr)

    def test_false_ci_does_not_trigger_ci_guard(self):
        """An explicit false CI value was treated as an affirmative CI declaration."""
        for value in ("false", "0"):
            result = self.run_script(env={**self.env, "CI": value, "AGY_BIN": "forbidden"})
            self.assertEqual(result.returncode, 3)
            self.assertNotIn("LOCAL_ONLY_CI", result.stderr)
            self.assertIn("overrides are not allowed", result.stderr)

    def test_legacy_overrides_are_rejected(self):
        """A caller override must fail visibly instead of silently changing binary selection."""
        for name in ("AGY_BIN", "GEMINI_CLI_BIN"):
            result = self.run_script(env={**self.env, name: "forbidden"})
            self.assertEqual(result.returncode, 3)
            self.assertIn("overrides are not allowed", result.stderr)


if __name__ == "__main__":
    unittest.main()
