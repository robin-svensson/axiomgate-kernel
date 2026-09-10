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
    """Racker loggens langd till for att ens innehalla den ankrade kedjan?

    Egen funktion for att den ska ga att stryka i ett mutationstest --
    scripts/mutate_r2.py. Ett skydd som aldrig setts falla ar inte visat.
    """
    return count >= anchor_count


def anchor_matches(at_anchor: Optional[str], anchor_head: Optional[str]) -> bool:
    """Ar posten pa den ankrade positionen den ankrade posten?

    Samma skal till egen funktion som anchor_covers.
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
        """`anchor` ar ett tidigare head() som hallits utanfor loggfilen.

        Anges det maste den befintliga filen BORJA med den ankrade kedjan,
        annars vagrar loggen oppna. Det ar det enda tillfalle en kapad svans
        annars aldrig upptacks: _replay() laser en avhuggen kedja utan att
        klaga, eftersom en avhuggen kedja ar internt konsistent.

        Utan ankare ar beteendet oforandrat -- en deklarerad lucka, samma
        sorts grans som require_principal_context. Se docs/ROADMAP.md R2.
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
        # Efter lakningen, aldrig fore: forsvann en ankrad post med den
        # ofullstandiga sista raden ar det ett fynd, inte en aterhamtning.
        if anchor is not None:
            ok, msg, _last, _count = self.verify_prefix(*anchor)
            if not ok:
                raise AuditError(f"audit log does not match its anchor: {msg}")

    def _replay(self) -> None:
        """Replay existing audit log to establish chain state."""
        ok, msg, last, count = self.verify_integrity()
        # Trunkering — en krasch mitt i en skrivning — rapporteras av
        # verify_integrity som "tail malformation" (sista raden är ofullständig
        # JSON utan något efter sig). En tidigare OR-gren letade efter
        # "truncation:", en sträng ingen emitter skriver; den var död kod.
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
            # Sju anropsställen lägger in fritext här: taggen f"repo:{repo_path}"
            # bär kundens sökväg, f"error:{str(e)}" bär vad undantaget råkade
            # innehålla. Inget av det ligger i report, så redact_dict(report)
            # täckte det aldrig. Loggen är hash-kedjad och HMAC-skyddad -- en
            # nyckel som hamnat här går inte att städa bort i efterhand -- så
            # redigeringen sitter på skrivpunkten, före hashberäkningen, och
            # gäller därmed varje anropare och varje framtida fält.
            record = redact_dict(record)
            body = {k: v for k, v in record.items() if k not in HASH_MAC_FIELDS}
            body["previous_hash"] = self._last_hash
            # Positionen ingar i det hashade innehallet. Utan den kan en kapad
            # svans inte skiljas fran en logg som aldrig varit langre -- se
            # verify_integrity och head().
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

        Spara det har utanfor loggfilen. Det ar det enda som gor en kapad
        svans upptackbar: kedjan i sig kan inte bevisa hur lang den ska vara.
        """
        with self._lock:
            return self._last_hash, self._count

    def verify_chain(
        self,
        expected_head: Optional[str] = None,
        expected_count: Optional[int] = None,
    ) -> Tuple[bool, str, Optional[str]]:
        """Verify audit chain integrity. Returns (ok, message, last_hash).

        Utan forankring bevisas bara att posterna som finns lanker rätt bakat.
        Ange expected_head/expected_count fran ett tidigare head()-anrop for
        att aven upptacka att slutet har kapats.
        """
        ok, msg, last, _count = self.verify_integrity(expected_head, expected_count)
        return ok, msg, last

    def verify_prefix(
        self,
        anchor_head: Optional[str] = None,
        anchor_count: Optional[int] = None,
    ) -> Tuple[bool, str, Optional[str], int]:
        """Borjar loggen med den kedja ankaret beskriver? (ok, msg, last, count)

        verify_chain svarar pa en annan fraga -- "ar detta EXAKT loggen jag
        ankrade?" -- och den gar inte att stalla om en logg som fortfarande
        anvands: nasta post gor svaret nej, och "log longer than anchor" ar
        da inte ett fynd utan bara att tiden gatt. Den har metoden later
        loggen ha vuxit, men kraver att posten pa den ankrade positionen ar
        den ankrade posten.

        Bada halvorna av ankaret kravs. En hash utan position sager inte var
        den skulle sitta, och en position utan hash sager inte vad som skulle
        sta dar -- ett halvt ankare ar inget ankare, och far darfor inte
        besvaras med ok.
        """
        # Granskningsfynd 2026-09-10: ett ogiltigt anchor_count var tekniskt
        # 'not None', slapp forbi halvankarkontrollen nedan och foll ut som
        # 'prefix mismatch: ... the log was replaced'. Kontrollen nekade ratt,
        # men meddelandet pastod manipulation dar felet var i anropet. Ett
        # anropsfel far inte lasas som ett fynd.
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
                # Ett ankare taget fore forsta posten. Aktarligt svar: det
                # finns inget att jamfora mot, sa ingen kapning kan
                # upptackas. Det ar inte ett fel -- men det ar inte ett bevis.
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
        """Ga kedjan igenom en gang. En sanningskalla for lankverifieringen.

        Returnerar (ok, msg, last_hash, count, hash_after_note_after) -- det
        sista ar hashen pa posten vid index note_after - 1, alltsa den post
        ett ankare med den langden ska peka pa. None om filen slutade forst.

        Anropas under self._lock av bade verify_integrity och verify_prefix.
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
                    # Posten skrevs innan sekvensnumret ingick i det hashade
                    # innehallet. Den kan inte efterhandsforses med ett -- da
                    # andras hashen -- och en sadan kedja kan alltsa inte
                    # provas mot kapning. Det ar ett formatbyte, inte
                    # manipulation, och skiljs darfor ut med ett eget
                    # meddelande.
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
