"""AxiomGate Kernel — Evidence Lifecycle Property Tests

Tests for evidence lifecycle security properties.
"""

import pytest
from datetime import datetime, timedelta, timezone

from axiomgate_kernel import (
    EvidenceJournal, EvidenceError, Principal, Role, Verdict,
)


class TestEvidenceLifecycle:
    """Test evidence lifecycle state transitions."""

    def _journal(self):
        return EvidenceJournal()

    def test_create_candidate(self):
        """Producer can create candidate evidence."""
        j = self._journal()
        record = j.create_candidate("ev-1", "agent-a", {"content": "test"})
        assert record.state.value == "CANDIDATE"
        assert record.producer_id == "agent-a"

    def test_duplicate_evidence_rejected(self):
        """Duplicate evidence ID is rejected."""
        j = self._journal()
        j.create_candidate("ev-1", "agent-a", {"content": "test"})
        with pytest.raises(EvidenceError, match="already exists"):
            j.create_candidate("ev-1", "agent-a", {"content": "test2"})

    def test_producer_cannot_verify_own(self):
        """Producer cannot verify own evidence."""
        j = self._journal()
        j.create_candidate("ev-1", "agent-a", {"content": "test"})
        with pytest.raises(EvidenceError, match="producer cannot verify"):
            j.verify("ev-1", Principal("agent-a"), Role.R_IV, True)

    def test_verify_requires_r_iv(self):
        """Verification requires R-IV role."""
        j = self._journal()
        j.create_candidate("ev-1", "agent-a", {"content": "test"})
        with pytest.raises(EvidenceError, match="verification requires R-IV"):
            j.verify("ev-1", Principal("agent-b"), Role.R_ENG, True)

    def test_verify_success(self):
        """Successful verification transitions to VERIFIED."""
        j = self._journal()
        j.create_candidate("ev-1", "agent-a", {"content": "test"})
        record = j.verify("ev-1", Principal("agent-b"), Role.R_IV, True)
        assert record.state.value == "VERIFIED"
        assert record.verifier_id == "agent-b"

    def test_verify_failure_stays_candidate(self):
        """Failed verification stays CANDIDATE."""
        j = self._journal()
        j.create_candidate("ev-1", "agent-a", {"content": "test"})
        record = j.verify("ev-1", Principal("agent-b"), Role.R_IV, False)
        assert record.state.value == "CANDIDATE"
        assert record.verification_result is False

    def test_producer_cannot_authorize(self):
        """Producer cannot be final authority."""
        j = self._journal()
        # Create evidence produced by owner
        j.create_candidate("ev-1", "owner", {"content": "test"})
        j.verify("ev-1", Principal("agent-b"), Role.R_IV, True)
        # Owner cannot authorize own evidence
        with pytest.raises(EvidenceError, match="producer cannot be final authority"):
            j.authorize("ev-1", Principal("owner"), Role.R_DEC, True)

    def test_authorize_requires_r_dec(self):
        """Authorization requires R-DEC role."""
        j = self._journal()
        j.create_candidate("ev-1", "agent-a", {"content": "test"})
        j.verify("ev-1", Principal("agent-b"), Role.R_IV, True)
        with pytest.raises(EvidenceError, match="requires Owner"):
            j.authorize("ev-1", Principal("agent-b"), Role.R_ENG, True)

    def test_riv_cannot_authorize(self):
        """R-IV cannot authorize evidence."""
        j = self._journal()
        j.create_candidate("ev-1", "agent-a", {"content": "test"})
        j.verify("ev-1", Principal("agent-b"), Role.R_IV, True)
        with pytest.raises(EvidenceError, match="R-IV cannot authorize"):
            j.authorize("ev-1", Principal("owner"), Role.R_IV, True)

    def test_authorize_requires_verified(self):
        """Authorization requires VERIFIED state."""
        j = self._journal()
        j.create_candidate("ev-1", "agent-a", {"content": "test"})
        with pytest.raises(EvidenceError, match="cannot authorize from"):
            j.authorize("ev-1", Principal("owner"), Role.R_DEC, True)

    def test_authorize_success(self):
        """Successful authorization transitions to AUTHORIZED."""
        j = self._journal()
        j.create_candidate("ev-1", "agent-a", {"content": "test"})
        j.verify("ev-1", Principal("agent-b"), Role.R_IV, True)
        record = j.authorize("ev-1", Principal("owner"), Role.R_DEC, True)
        assert record.state.value == "AUTHORIZED"

    def test_evidence_events_append_only(self):
        """Evidence events are append-only."""
        j = self._journal()
        j.create_candidate("ev-1", "agent-a", {"content": "test"})
        j.verify("ev-1", Principal("agent-b"), Role.R_IV, True)
        j.authorize("ev-1", Principal("owner"), Role.R_DEC, True)
        events = j.events()
        assert len(events) == 3
        assert events[0].event == "create_candidate"
        assert events[1].event == "verified"
        assert events[2].event == "authorized"

    def test_evidence_record_immutable(self):
        """Evidence records are detached and strictly immutable."""
        from dataclasses import FrozenInstanceError, fields

        j = self._journal()
        raw_content = {"content": "test", "nested": [1, 2, 3]}
        record = j.create_candidate("ev-1", "agent-a", raw_content)

        # 1. Verify every field raises FrozenInstanceError upon attempted mutation
        for f in fields(record):
            with pytest.raises(FrozenInstanceError):
                setattr(record, f.name, "mutated_value")

        # 2. Verify mutating input object does not mutate record content (defensive copy)
        raw_content["content"] = "tampered"
        raw_content["nested"].append(4)
        fetched = j.get("ev-1")
        assert fetched is not None
        assert fetched.content["content"] == "test"
        assert fetched.content["nested"] == [1, 2, 3]

