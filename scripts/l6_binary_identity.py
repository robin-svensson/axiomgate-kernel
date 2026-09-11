#!/usr/bin/env python3
"""Check a reviewed local executable or package fingerprint without executing it.

Pins identify inventoried bytes, not publisher signatures or backend vendors.
This detects installation drift; it is not a sandbox against concurrent hostile
writes. A check followed by launch is not atomic. Dynamic libraries, service
configuration and child commands are outside this executable/package inventory.
"""

import hashlib
import os
from pathlib import Path
import stat
import sys


def digest_file(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.digest()


def canonical_path(path):
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("expected an absolute path with a non-symlink final entry")
    # mise/latest may occur in a parent directory. Resolve it explicitly;
    # the final entry must remain a real file/directory and still match its pin.
    return path.resolve(strict=True)


def safe_mode(path):
    mode = path.stat().st_mode
    # These bits affect privilege or who may replace the bytes. Normal read/
    # execute changes are not content identity and do not require re-pinning.
    # This is not a complete ACL, ownership, parent-directory or mount audit.
    if mode & (stat.S_ISUID | stat.S_ISGID | stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("PIN_UNSAFE_PERMISSIONS: " + str(path))
    return mode


def fingerprint(kind, path):
    path = canonical_path(path)
    safe_mode(path)
    if kind == "file":
        if not stat.S_ISREG(path.stat().st_mode) or not os.access(path, os.X_OK):
            raise ValueError("expected an executable regular file")
        with path.open("rb") as source:
            if source.read(4) != b"\x7fELF":
                raise ValueError("expected a native ELF executable, not a launcher shim")
        return digest_file(path).hex()
    if kind != "tree" or not path.is_dir():
        raise ValueError("expected file or tree and an existing matching path")
    value = hashlib.sha256()
    count = 0
    # os.walk reports traversal failures; silently skipped directories must not
    # turn an unreadable package into a matching partial inventory.
    def unreadable(error):
        raise error
    files = []
    for parent, directories, names in os.walk(path, onerror=unreadable):
        for name in directories + names:
            entry = Path(parent) / name
            mode = entry.lstat().st_mode
            if stat.S_ISLNK(mode):
                raise ValueError("package symlink is not allowed: " + str(entry))
            safe_mode(entry)
            if stat.S_ISREG(mode):
                files.append(entry)
            elif not stat.S_ISDIR(mode):
                raise ValueError("package contains a non-regular entry: " + str(entry))
    for entry in sorted(files):
        name = entry.relative_to(path).as_posix().encode()
        value.update(len(name).to_bytes(8, "big"))
        value.update(name)
        value.update(digest_file(entry))
        count += 1
    if not count:
        raise ValueError("empty package")
    return value.hexdigest()


def valid_pin(value):
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def main():
    try:
        # Observation mode never changes the allowlist or labels bytes trusted.
        if len(sys.argv) == 4 and sys.argv[1] == "--fingerprint":
            kind, raw_path = sys.argv[2:]
            resolved = canonical_path(Path(raw_path))
            actual = fingerprint(kind, resolved)
            print(f"UNVERIFIED_CANDIDATE: {kind} {resolved} sha256={actual}")
            return 0
        if len(sys.argv) not in (4, 5):
            raise ValueError("expected: file|tree ABSOLUTE_PATH PIN [APPROVED_UPDATE]")
        kind, raw_path, expected = sys.argv[1:4]
        approved = sys.argv[4] if len(sys.argv) == 5 else ""
        if not valid_pin(expected) or (approved and not valid_pin(approved)):
            raise ValueError("missing or invalid reviewed SHA-256 pin/update record")
        resolved = canonical_path(Path(raw_path))
        actual = fingerprint(kind, resolved)
        if actual != expected:
            if approved and actual == approved:
                raise ValueError(
                    "PIN_STALE_APPROVED_UPDATE: bytes match the reviewed update record; "
                    "apply the approved re-pinning diff before retrying: " + raw_path
                )
            raise ValueError(
                f"PIN_CONTENT_CHANGED_UNVERIFIED: {raw_path} "
                f"expected={expected} actual={actual}; "
                "update legitimacy is unknown; investigate and follow the re-pinning "
                "procedure in l6-review.sh, never auto-accept this hash"
            )
        print(f"identity: {kind} {resolved} sha256={actual}", flush=True)
        return 0
    except FileNotFoundError as error:
        print(
            f"BLOCKED: PIN_TARGET_MISSING: {error}; restore the pinned installation "
            "or follow the approved re-pinning procedure in l6-review.sh",
            file=sys.stderr,
        )
        return 3
    except (OSError, ValueError) as error:
        print(f"BLOCKED: reviewer identity could not be verified: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
