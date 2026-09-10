#!/usr/bin/env python3
"""Refuse to let the package root itself in anyone else's home directory but its own.

The bug this file exists for: `config.py` pointed its key paths into a
private tooling environment on the author's machine, so a fresh install read
and wrote keys in a directory the installing user had never heard of.

The first guard against this named that directory right in the assertion.
That was wrong in two ways. It caught *only* that directory, and it carried
an internal codename into a public repo. The second guard instead searched
the source with a regular expression -- and a review showed that six of
eight ways of writing it slipped past:

    Path.home() / '.foo'                              single quotes
    os.path.join(os.path.expanduser('~'), '.foo')     two-argument form
    os.path.join(str(Path.home()), ".foo")            str(Path.home())
    f"~/{name}/.foo"                                  f-string
    os.environ["HOME"] + "/.foo"                       HOME from the environment
    "~" + "/.foo"                                     concatenation

A regular expression sees how the string is *written*. We need to know which
directory the package *ends up* in. So the code is instead read as a syntax
tree: the ways of writing it above only differ in spelling, but all six are
the same thing in the tree -- an expression that joins a home reference with
a string constant.

The rule, and why it is written this way:

1. Only expressions that *contain* a home reference are examined. `.tmp` in
   `audit.py` and `.error` in `mediator.py` are file extensions that never
   meet a home directory, and a pattern that tripped on them would have
   forced exceptions per filename -- and an exception is exactly what the
   next regression hides in.
2. Of such an expression, only the *first* dot segment of each string is
   examined. That is the root under the home directory and the only thing
   that decides whose directory the package settles into. What lies *inside*
   our own directory -- `.approval_...key` is a hidden file there -- is our
   own business.
3. Exactly one file in the package may reference the home directory. Without
   that condition, the directory name could sit in one file and the home
   reference in another, both conditions could be satisfied, and the bug
   would still be there.

Exit 0 = the package roots itself only in its own directory. Exit 1 = at
least one foreign one.
"""
import ast
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG = ROOT / "axiomgate_kernel"

# The directory the package owns. Everything else belongs to someone else.
OWN = ".axiomgate-kernel"

# A dot segment in a path: `.name` as a whole part between slashes.
# `foo.tmp` is an extension and does not match; `.tmp` and `x/.tmp` do.
SEGMENT = re.compile(r"(?:^|/)(\.[A-Za-z0-9_][A-Za-z0-9_.-]*)(?=/|$)")

# The paths Python offers to the user's home directory: `Path.home()`,
# `os.path.expanduser`, HOME from the environment, and the tilde written by hand.
HOME_ATTRS = {"home", "expanduser", "expandvars"}
HOME_NAMES = {"HOME", "USERPROFILE"}


def references_home(node: ast.AST) -> bool:
    """Whether the subtree can find out where the home directory is at all."""
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute) and child.attr in HOME_ATTRS:
            return True
        if isinstance(child, ast.Name) and child.id in HOME_ATTRS:
            return True
        if isinstance(child, ast.Constant) and isinstance(child.value, str):
            if "~" in child.value or child.value in HOME_NAMES:
                return True
    return False


def home_roots(node: ast.AST) -> set[str]:
    """The dot directories a subtree roots a path in.

    The recursion stops at the outermost expression that references the home
    directory: that is the whole join, and it is where both the home
    reference and the directory name are visible together. Going deeper
    would separate them -- in `os.path.join(expanduser('~'), '.foo')` they
    sit in different arguments.
    """
    if isinstance(node, ast.expr) and references_home(node):
        roots = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                found = SEGMENT.findall(child.value)
                if found:
                    roots.add(found[0])
        return roots

    roots = set()
    for child in ast.iter_child_nodes(node):
        roots |= home_roots(child)
    return roots


def files_referencing_home(tree: ast.AST) -> bool:
    return references_home(tree)


def main() -> int:
    if not PKG.is_dir():
        print(f"ERROR: cannot find the package {PKG}")
        return 1

    files = sorted(PKG.rglob("*.py"))
    if not files:
        # If the search stopped finding files, silence would be a false pass.
        print("ERROR: no source files to check -- the search no longer matches")
        return 1

    home_files: list[str] = []
    failed = 0

    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if not files_referencing_home(tree):
            continue
        home_files.append(path.name)

        foreign = sorted(r for r in home_roots(tree) if r != OWN)
        if foreign:
            failed += 1
            print(f"FOREIGN  {path.relative_to(ROOT)}  {foreign}  -- not {OWN}")

    if not home_files:
        # The package must know where the home directory is; if it stopped
        # doing that, the check has stopped testing anything, and silence is
        # then no pass.
        print("ERROR: no file references a home directory -- the check tests nothing")
        return 1

    if len(home_files) != 1:
        failed += 1
        print(f"SCATTERED HOME REFERENCE  {home_files}  -- only one file may know where home is")

    print(f"{len(home_files)} file(s) with a home reference checked, {failed} errors")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
