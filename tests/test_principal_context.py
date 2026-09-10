"""parse_mandate -- format parsing of mandate strings.

Three defects in the same function, all found through an external audit on
2026-09-09 and verified by live execution.
"""

from datetime import datetime, timezone
import subprocess
import sys

import pytest

from axiomgate_kernel.principal_context import parse_mandate


class TestParseMandateTimestamp:
    """split(':') chops up the ISO timestamp, which itself contains colons.

    'execute:expires:2026-12-31T23:59:59Z' -> parts[2] becomes '2026-12-31T23'
    and expires_at lands on 23:00:00Z. 59 minutes 59 seconds are silently
    dropped, and the mandate expires earlier than it claims.
    """

    def test_full_iso_timestamp_is_preserved(self):
        m = parse_mandate("execute:expires:2026-12-31T23:59:59Z")
        assert m is not None
        assert m.expires_at == datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc)

    def test_parent_is_found_after_iso_timestamp(self):
        """parts[3] == 'parent' never holds once the timestamp ate indices 2-4.

        The provenance chain breaks silently: parent_mandate_id becomes None
        without an error code, so a delegated authorization looks like a
        root mandate.
        """
        m = parse_mandate("execute:expires:2026-12-31T23:59:59Z:parent:abc")
        assert m is not None
        assert m.parent_mandate_id == "abc"
        assert m.expires_at == datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc)


class TestParseMandateUnknownFormat:
    """The docstring's example 'execute:2026-12-31T23:59:59Z' is missing
    'expires'.

    The branch requires parts[1] == 'expires', so the timestamp is ignored
    entirely and expires_at becomes None while is_valid is True. A mandate
    that looks time-bound never expires -- fail-open in the mandate layer.
    """

    def test_timestamp_without_expires_is_rejected(self):
        assert parse_mandate("execute:2026-12-31T23:59:59Z") is None

    def test_naked_scope_is_still_valid(self):
        m = parse_mandate("execute")
        assert m is not None
        assert m.expires_at is None
        assert m.is_valid is True


class TestParseMandateIdStability:
    """mandate_id is built on hash(), which is randomized per process
    (PYTHONHASHSEED).

    The same mandate string gets different ids in two processes, so an id
    can neither be cross-referenced in the audit log nor matched against
    parent_mandate_id across a process switch.
    """

    def test_same_string_gives_same_id_across_processes(self):
        code = (
            "from axiomgate_kernel.principal_context import parse_mandate;"
            "print(parse_mandate('execute:expires:2026-12-31T23:59:59Z').mandate_id)"
        )
        ids = {
            subprocess.run([sys.executable, "-c", code], capture_output=True,
                           text=True, check=True).stdout.strip()
            for _ in range(3)
        }
        assert len(ids) == 1, f"mandate_id varies between processes: {ids}"
