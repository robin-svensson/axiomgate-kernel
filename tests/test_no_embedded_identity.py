"""No real-world identity may be embedded in the shipped package.

Bug this file exists for (found 2026-09-10): `ApprovalVerifier` fell back to a
hard-coded platform user id when neither `trusted_owner_id` nor the environment
variable was set. In an installation that configured neither, the only trusted
approver was a *stranger's* identity shipped inside the package. That is
fail-open against an outside party -- the opposite of what the rest of the
kernel does. Absence of an owner must refuse, not substitute one.
"""
import os
import pathlib
import re

import pytest

from axiomgate_kernel.approval import ApprovalVerifier

PKG = pathlib.Path(__file__).resolve().parent.parent / "axiomgate_kernel"

# Any 15-20 digit run is a platform user id -- chat platforms and directory
# services both mint ids in that range. None of them belong in this package.
_ID_LIKE = re.compile(r"\b\d{15,20}\b")


def test_verifier_refuses_to_construct_without_a_trusted_owner(monkeypatch):
    monkeypatch.delenv("AXIOMGATE_OWNER_ID", raising=False)
    with pytest.raises(ValueError, match="trusted owner"):
        ApprovalVerifier(public_key_bytes=b"\x01" * 32)


def test_explicit_owner_still_works():
    v = ApprovalVerifier(public_key_bytes=b"\x01" * 32, trusted_owner_id="owner-under-test")
    assert v._trusted_owner_id == "owner-under-test"


def test_environment_still_configures_the_owner(monkeypatch):
    monkeypatch.setenv("AXIOMGATE_OWNER_ID", "env-owner")
    v = ApprovalVerifier(public_key_bytes=b"\x01" * 32)
    assert v._trusted_owner_id == "env-owner"


def test_empty_owner_is_absence_not_a_value(monkeypatch):
    """An empty string must not become a trusted principal."""
    monkeypatch.delenv("AXIOMGATE_OWNER_ID", raising=False)
    with pytest.raises(ValueError, match="trusted owner"):
        ApprovalVerifier(public_key_bytes=b"\x01" * 32, trusted_owner_id="   ")


@pytest.mark.parametrize("path", sorted(PKG.rglob("*.py")), ids=lambda p: p.name)
def test_no_platform_user_id_is_embedded_in_the_package(path):
    """No shipped source file may carry a real account id."""
    hits = _ID_LIKE.findall(path.read_text(encoding="utf-8"))
    assert not hits, f"{path.name} embeds identity-like value(s): {hits}"


# Every home-directory default the package writes, in either spelling:
# `~/.something` in a docstring, or `Path.home() / ".something"` in code.
_DOTDIR = r'\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*'
_HOME_DOTDIR = re.compile(rf'~/({_DOTDIR})|Path\.home\(\)\s*/\s*"({_DOTDIR})"')

# The one directory this package owns. Anything else is another tool's.
OWN_DOTDIR = ".axiomgate-kernel"


@pytest.mark.parametrize("path", sorted(PKG.rglob("*.py")), ids=lambda p: p.name)
def test_no_foreign_home_directory_is_embedded(path):
    """The package may default into its own dot directory and no one else's.

    Bug this guard exists for: config.py defaulted into a private tool
    environment on the author's machine, so a fresh install read and wrote keys
    somewhere the installing user had never heard of. Naming that one directory
    in the assertion would only catch that one directory -- and would carry the
    name into a public repository. Any foreign dot directory is the bug.
    """
    text = path.read_text(encoding="utf-8")
    found = {a or b for a, b in _HOME_DOTDIR.findall(text)}
    foreign = sorted(d for d in found if d != OWN_DOTDIR)
    assert not foreign, f"{path.name} defaults into {foreign}, not ~/{OWN_DOTDIR}"
