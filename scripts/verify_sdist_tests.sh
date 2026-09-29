#!/usr/bin/env bash
set -euo pipefail

sdist="${1:?usage: verify_sdist_tests.sh PATH/TO/axiomgate-kernel-*.tar.gz}"
[[ -f "$sdist" ]] || { echo "FAIL: sdist does not exist: $sdist" >&2; exit 2; }
[[ -n "${TMPDIR:-}" && -d "$TMPDIR" ]] || {
  echo "FAIL: set TMPDIR to a writable directory outside the repository" >&2
  exit 2
}

work="$(mktemp -d "$TMPDIR/axiomgate-kernel-sdist.XXXXXX")"
mkdir "$work/source"
tar -xzf "$sdist" -C "$work/source"
mapfile -t roots < <(find "$work/source" -mindepth 1 -maxdepth 1 -type d -print)
[[ "${#roots[@]}" -eq 1 ]] || {
  echo "FAIL: sdist must unpack to exactly one source directory" >&2
  exit 1
}
source_root="${roots[0]}"

python3 -m venv "$work/venv"
export PIP_CACHE_DIR="$work/pip-cache"
env -u PYTHONPATH -u PYTHONHOME "$work/venv/bin/python" -m pip install \
  --disable-pip-version-check -e "$source_root[dev]"
version="$(env -u PYTHONPATH -u PYTHONHOME "$work/venv/bin/python" -c \
  'from importlib.metadata import version; print(version("axiomgate-kernel"))')"
[[ "$version" == "0.12.0" ]] || {
  echo "FAIL: expected sdist version 0.12.0, got $version" >&2
  exit 1
}
env -u PYTHONPATH -u PYTHONHOME "$work/venv/bin/python" -m pip check

echo "== Running the complete test suite from unpacked sdist $source_root =="
cd "$source_root"
env -u PYTHONPATH -u PYTHONHOME "$work/venv/bin/python" -m pytest -q -p no:cacheprovider
echo "PASS: complete sdist test suite; work directory: $work"
