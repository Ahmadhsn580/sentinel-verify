#!/usr/bin/env bash
set -euo pipefail

REPO_NAME="sentinel-verify"

is_termux() { case "${PREFIX:-}" in *com.termux*) return 0 ;; *) return 1 ;; esac; }

if is_termux; then
  BIN_DIR="${PREFIX}/bin"
else
  BIN_DIR="${HOME}/.local/bin"
fi

rm -f "${BIN_DIR}/${REPO_NAME}"

DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/${REPO_NAME}"
REPORTS_DIR="${DATA_DIR}/reports"
if [ -d "$REPORTS_DIR" ]; then
  printf 'Reports kept at %s\n' "$REPORTS_DIR"
  rm -rf "${DATA_DIR}/venv"
else
  rm -rf "$DATA_DIR"
fi

printf 'Uninstalled. Reports (if any) were preserved.\n'