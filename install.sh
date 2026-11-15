#!/usr/bin/env bash
set -euo pipefail

REPO_NAME="sentinel-verify"
MIN_PY_MINOR=10

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

is_termux() { case "${PREFIX:-}" in *com.termux*) return 0 ;; *) return 1 ;; esac; }

PY=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, ${MIN_PY_MINOR}) else 1)" 2>/dev/null; then
      PY="$candidate"
      break
    fi
  fi
done
[ -n "$PY" ] || die "python >= 3.${MIN_PY_MINOR} is required"

if is_termux; then
  say "Termux detected (prefix: $PREFIX)"
  command -v pkg >/dev/null 2>&1 && say "hint: pkg install python git openssl"
  BIN_DIR="${PREFIX}/bin"
else
  BIN_DIR="${HOME}/.local/bin"
fi
mkdir -p "$BIN_DIR"

VENV_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/${REPO_NAME}/venv"
mkdir -p "$(dirname "$VENV_DIR")"
"$PY" -m venv --clear "$VENV_DIR"
# shellcheck disable=SC1091
. "${VENV_DIR}/bin/activate"
python -m pip install --quiet --upgrade pip
python -m pip install --quiet --no-deps -e .

ln -sf "${VENV_DIR}/bin/${REPO_NAME}" "${BIN_DIR}/${REPO_NAME}"

say ""
say "Installed to ${BIN_DIR}/${REPO_NAME}"
case ":${PATH}:" in
  *":${BIN_DIR}:"*) ;;
  *) say "Add this to your shell rc:  export PATH=\"${BIN_DIR}:\$PATH\"" ;;
esac
say "Try:  ${REPO_NAME} list-checks"