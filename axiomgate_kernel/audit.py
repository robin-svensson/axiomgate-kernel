"""AxiomGate Kernel — Audit Log

Append-only, hash-chained, HMAC-protected audit log.
"""

import json
import os
import tempfile
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

from .redaction import redact_dict

from .canonical import canonical_bytes, canonical_json
from .crypto import hmac_equal, hmac_sha256_hex, sha256_hex

HASH_MAC_FIELDS = frozenset({"entry_hash", "mac"})


class AuditError(Exception):
    """Raised when audit operations fail."""
    pass


def anchor_covers(count: int, anchor_count: int) -> bool:
    """Is the log even long enough to contain the anchored chain?

    Kept as its own function so it can be struck out in a mutation test --
    scripts/mutate_r2.py. A protection never seen to fail has not been shown.
    """
    return count >= anchor_count


def anchor_matches(at_anchor: Optional[str], anchor_head: Optional[str]) -> bool:
    """Is the entry at the anchored position the anchored entry?

    Same reason for its own function as anchor_covers.
    """
    return at_anchor == anchor_head


class AuditLog:
    """Append-only, hash-chained, HMAC-protected audit log.

    Properties:
    - Append-only (no deletion or modification)
    - Hash chain (each entry links to previous)
    - HMAC on each entry (tamper-evident)
    - Atomic append with fsync
    - Crash recovery (truncation and tail malformation healing)
    """

    def __init__(
        self,
        path: str,
        mac_key: bytes,
        writer: Optional[Callable[[str, str], None]] = None,
        anchor: Optional[Tuple[Optional[str], int]] = None,
    ) -> None:
        """`anchor` is a prior head() that was kept outside the log file.

        If given, the existing file MUST START with the anchored chain, or the
        log refuses to open. This is the only case where a truncated tail
        would otherwise never be detected: _replay() reads a chopped chain
        without complaint, because a chopped chain is internally consistent.

        Without an anchor, behavior is unchanged -- a declared gap, the same
        kind of boundary as require_principal_context. See docs/ROADMAP.md R2.
        """
        if not mac_key:
            raise AuditError("audit MAC key must be initialized before any write")
        self.path = path
        self._mac_key = bytes(mac_key)
        self._writer = writer or _atomic_append
        self._last_hash: Optional[str] = None
        self._count = 0
        self._lock = threading.RLock()
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        if os.path.exists(path):
            self._replay()
        # After healing, never before: if an anchored entry disappeared along
        # with the incomplete last line, that is a finding, not a recovery.
        if anchor is not None:
            ok, msg, _last, _count = self.verify_prefix(*anchor)
            if not ok:
                raise AuditError(f"audit log does not match its anchor: {msg}")

    def _replay(self) -> None:
        """Replay existing audit log to establish chain state."""
        ok, msg, last, count = self.verify_integrity()
        # Truncation -- a crash mid-write -- is reported by verify_integrity
        # as "tail malformation" (the last line is incomplete JSON with
        # nothing after it). An earlier OR branch looked for "truncation:", a
        # string no emitter writes; it was dead code.
        recoverable = (not ok) and ("tail malformation" in msg)
        if (not ok) and "legacy chain format" in msg:
            raise AuditError(
                f"existing audit chain is in the pre-sequence format: {msg}. "
                "It cannot be migrated in place -- rewriting the entries would "
                "break the hashes that are the evidence. Archive the file and "
                "start a new chain, keeping the old one as a sealed record."
            )
        if not ok and not recoverable:
            raise AuditError(f"existing audit chain is invalid: {msg}")

        if "tail malformation" in msg:
            # Heal the mid-write crash by retaining only the valid lines
            valid_lines = []
            with open(self.path, "r", encoding="utf-8") as handle:
                for _ in range(count):
                    valid_lines.append(handle.readline())

            directory = os.path.dirname(self.path) or "."
            fd, tmp = tempfile.mkstemp(dir=directory, prefix=".audit.", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.writelines(valid_lines)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, self.path)
            except Exception:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise

        self._last_hash = last
        self._count = count

    def append(self, record: Dict[str, Any]) -> str:
        """Append a record to the audit log.

        Returns the entry hash. Thread-safe.
        Raises AuditError on failure.
        """
        with self._lock:
            if not self._mac_key:
                raise AuditError("audit MAC key missing")
            # Seven call sites put free text in here: the tag f"repo:{repo_path}"
            # carries the customer's path, f"error:{str(e)}" carries whatever the
            # exception happened to contain. None of that lives in report, so
            # redact_dict(report) never covered it. The log is hash-chained and HMAC-
            # protected -- a key that ends up here cannot be cleaned out after the fact
            # -- so the redaction sits at the write point, before the hash computation,
            # and therefore applies to every caller and every future field.
            record = redact_dict(record)
            body = {k: v for k, v in record.items() if k not in HASH_MAC_FIELDS}
            body["previous_hash"] = self._last_hash
            # The position is part of the hashed content. Without it, a
            # truncated tail cannot be distinguished from a log that was
            # never any longer -- see verify_integrity and head().
            body["seq"] = self._count
            entry_hash = sha256_hex(canonical_bytes(body))
            mac = hmac_sha256_hex(self._mac_key, canonical_bytes({**body, "entry_hash": entry_hash}))
            stored = {**body, "entry_hash": entry_hash, "mac": mac}
            line = canonical_json(stored) + "\n"
            try:
                self._writer(self.path, line)
                self._last_hash = entry_hash
                self._count += 1
            except Exception as exc:
                raise AuditError(f"audit write failed: {exc}") from exc
            return entry_hash

    def append_approval_event(
        self,
        event_type: str,
        escalation_id: str,
        tool: str,
        decision: str,
        approver: str,
        signature_prefix: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Record an approval verification or consumption event in the audit chain.

        Ensures signature prefixes or digests are logged, but NEVER private keys.
        """
        record: Dict[str, Any] = {
            "event_type": event_type,
            "escalation_id": escalation_id,
            "tool": tool,
            "decision": decision,
            "approver": approver,
            "signature_prefix": signature_prefix[:16] if signature_prefix else "",
            "details": details or {},
        }
        return self.append(record)


    def entries(self) -> List[dict]:
        """Read all audit entries. Thread-safe."""
        with self._lock:
            if not os.path.exists(self.path):
                return []
            out = []
            with open(self.path, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    out.append(json.loads(line))
            return out

    def head(self) -> Tuple[Optional[str], int]:
        """Return (last_entry_hash, entry_count) -- the anchor for this log.

        Save this outside the log file. It is the only thing that makes a truncated
        tail detectable: the chain itself cannot prove how long it is supposed to be.
        """
        with self._lock:
            return self._last_hash, self._count

    def verify_chain(
        self,
        expected_head: Optional[str] = None,
        expected_count: Optional[int] = None,
    ) -> Tuple[bool, str, Optional[str]]:
        """Verify audit chain integrity. Returns (ok, message, last_hash).

        Without anchoring, this only proves that the entries present link
        correctly backward. Pass expected_head/expected_count from a prior
        head() call to also detect that the end has been truncated.
        """
        ok, msg, last, _count = self.verify_integrity(expected_head, expected_count)
        return ok, msg, last

    def verify_prefix(
        self,
        anchor_head: Optional[str] = None,
        anchor_count: Optional[int] = None,
    ) -> Tuple[bool, str, Optional[str], int]:
        """Does the log begin with the chain the anchor describes? (ok, msg, last, count)

        verify_chain answers a different question -- "is this EXACTLY the
        log I anchored?" -- and that cannot be asked of a log still in use:
        the next entry makes the answer no, and "log longer than anchor" is
        then not a finding but just that time has passed. This method lets
        the log have grown, but requires that the entry at the anchored
        position be the anchored entry.

        Both halves of the anchor are required. A hash without a position
        does not say where it should sit, and a position without a hash does
        not say what should be there -- half an anchor is no anchor, and
        must therefore not be answered with ok.
        """
        # Review finding 2026-09-10: an invalid anchor_count was technically
        # 'not None', slipped past the half-anchor check below, and fell
        # through as 'prefix mismatch: ... the log was replaced'. The check
        # denied correctly, but the message claimed tampering when the error
        # was in the call. A caller error must not be read as a finding.
        if anchor_count is not None and anchor_count < 0:
            return (
                False,
                f"invalid anchor: anchor_count is {anchor_count}, and a log "
                "cannot have fewer than zero entries",
                None,
                0,
            )
        if anchor_head is not None and anchor_count == 0:
            return (
                False,
                "invalid anchor: anchor_count is 0 but anchor_head is set -- "
                "there is no entry at position zero for that hash to be",
                None,
                0,
            )
        if anchor_head is None or anchor_count is None:
            if anchor_head is None and anchor_count == 0:
                # An anchor taken before the first entry. Honest answer: there
                # is nothing to compare against, so no truncation can be
                # detected. It is not an error -- but it is not proof either.
                _ok, msg, last, count, _at = self._verify_links()
                if not _ok:
                    return _ok, msg, last, count
                return (
                    True,
                    f"anchor of zero entries proves nothing: {count} entries "
                    "in the log, none of them anchored",
                    last,
                    count,
                )
            return (
                False,
                "prefix verification needs both halves of the anchor "
                "(head and count from a single head() call)",
                None,
                0,
            )
        with self._lock:
            ok, msg, last, count, at_anchor = self._verify_links(note_after=anchor_count)
            if not ok:
                return ok, msg, last, count
            if not anchor_covers(count, anchor_count):
                return (
                    False,
                    f"log truncated: {count} entries, anchor expected at least {anchor_count}",
                    last,
                    count,
                )
            if not anchor_matches(at_anchor, anchor_head):
                return (
                    False,
                    "prefix mismatch: the entry at the anchored position is not "
                    "the anchored entry -- the log was replaced, not appended to",
                    last,
                    count,
                )
            return (
                True,
                f"prefix ok: {anchor_count} anchored entries verified, "
                f"{count - anchor_count} appended since",
                last,
                count,
            )

    def verify_integrity(
        self,
        expected_head: Optional[str] = None,
        expected_count: Optional[int] = None,
    ) -> Tuple[bool, str, Optional[str], int]:
        """Full integrity verification. Thread-safe.

        Returns (ok, message, last_hash, entry_count).
        """
        with self._lock:
            if not os.path.exists(self.path):
                return True, "empty", None, 0
            ok, msg, last, count, _at = self._verify_links()
            if not ok:
                return ok, msg, last, count

            if expected_count is not None and count < expected_count:
                return (
                    False,
                    f"log truncated: {count} entries, anchor expected {expected_count}",
                    last,
                    count,
                )
            if expected_count is not None and count > expected_count:
                return (
                    False,
                    f"log longer than anchor: {count} entries, anchor expected {expected_count}",
                    last,
                    count,
                )
            if expected_head is not None and last != expected_head:
                return False, "head mismatch: log does not end at the anchored entry", last, count

            return True, "ok", last, count

    def _verify_links(
        self,
        note_after: Optional[int] = None,
    ) -> Tuple[bool, str, Optional[str], int, Optional[str]]:
        """Walk the chain once. A single source of truth for link verification.

        Returns (ok, msg, last_hash, count, hash_after_note_after) -- the
        last item is the hash of the entry at index note_after - 1, i.e. the
        entry an anchor of that length should point to. None if the file
        ended first.

        Called under self._lock by both verify_integrity and verify_prefix.
        """
        if not os.path.exists(self.path):
            return True, "empty", None, 0, None

        at_note: Optional[str] = None
        prev: Optional[str] = None
        last: Optional[str] = None
        count = 0
        with open(self.path, "r", encoding="utf-8") as handle:
            for index, line in enumerate(handle):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    remainder = handle.read().strip()
                    if not remainder:
                        return False, f"tail malformation at {index}", last, count, at_note
                    return False, f"malformed json at {index}", last, count, at_note
                if entry.get("previous_hash") != prev:
                    return False, f"previous_hash mismatch at {index}", last, count, at_note
                if "seq" not in entry:
                    # The entry was written before the sequence number was
                    # part of the hashed content. It cannot be retrofitted
                    # with one -- that would change the hash -- so such a
                    # chain cannot be checked for truncation. It is a format
                    # change, not tampering, and is therefore distinguished
                    # with its own message.
                    return (
                        False,
                        f"legacy chain format at {index}: entry predates "
                        "sequence numbering and cannot be checked for "
                        "truncation",
                        last,
                        count,
                        at_note,
                    )
                if entry["seq"] != count:
                    return False, f"seq mismatch at {index}", last, count, at_note
                body = {k: v for k, v in entry.items() if k not in HASH_MAC_FIELDS}
                expected_hash = sha256_hex(canonical_bytes(body))
                if entry.get("entry_hash") != expected_hash:
                    return False, f"entry_hash mismatch at {index}", last, count, at_note
                expected_mac = hmac_sha256_hex(
                    self._mac_key,
                    canonical_bytes({**body, "entry_hash": expected_hash}),
                )
                if not hmac_equal(expected_mac, str(entry.get("mac", ""))):
                    return False, f"mac mismatch at {index}", last, count, at_note
                prev = entry["entry_hash"]
                last = prev
                count += 1
                if note_after is not None and count == note_after:
                    at_note = prev

        return True, "ok", last, count, at_note


def _atomic_append(path: str, line: str) -> None:
    """Atomic append to audit log file."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())
