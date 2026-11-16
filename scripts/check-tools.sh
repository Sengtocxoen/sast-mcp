#!/usr/bin/env bash
# Read-only report: for every scanner the server knows about, say whether it is
# on PATH, and if not, whether a working binary exists somewhere PATH misses.
#
# Why this exists
# ---------------
# install_tools.sh used to decide "installed" from `command -v` alone, under
# sudo's secure_path. Tools that install into a prefix of their own (gem, npm,
# go, pipx) were therefore reported as failures while being perfectly
# installed: in the 2026-11-15 run, tfsec and bearer both printed their own
# "installed at /usr/local/bin" line and still showed up in the failed list.
#
# This script answers the only question that matters: can the server execute
# the tool, and from where. Run it as the user the server runs as.
#
# Usage: scripts/check-tools.sh [--versions]

set -uo pipefail

SHOW_VERSIONS=0
[ "${1:-}" = "--versions" ] && SHOW_VERSIONS=1

TOOLS=(
  opengrep semgrep bandit bearer graudit gosec brakeman eslint
  trufflehog gitleaks safety checkov tfsec trivy
  nikto nmap sqlmap wpscan dirb lynis clamscan snyk
  dependency-check.sh npm
)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_USER="$(id -un)"
INSTALL_USER="${SUDO_USER:-$RUN_USER}"
INSTALL_USER_HOME="$(getent passwd "$INSTALL_USER" 2>/dev/null | cut -d: -f6)"
[ -n "$INSTALL_USER_HOME" ] || INSTALL_USER_HOME="${HOME:-/root}"

# Every directory an installer in tools/install_tools.sh can write to.
SEARCH_DIRS=(
  "${REPO_ROOT}/venv/bin"
  /usr/local/bin /usr/bin /bin /usr/local/sbin /usr/sbin /snap/bin
  /root/.local/bin /root/go/bin /usr/local/go/bin
  "${INSTALL_USER_HOME}/.local/bin" "${INSTALL_USER_HOME}/go/bin"
)
GEM_BIN="$(gem environment gemdir 2>/dev/null)/bin"
NPM_BIN="$(npm prefix -g 2>/dev/null)/bin"
[ -d "$GEM_BIN" ] && SEARCH_DIRS+=("$GEM_BIN")
[ -d "$NPM_BIN" ] && SEARCH_DIRS+=("$NPM_BIN")

echo "running as   : $RUN_USER"
echo "install user : $INSTALL_USER (home $INSTALL_USER_HOME)"
echo "PATH         : $PATH"
echo

on_path=0
off_path=0
missing=0

for tool in "${TOOLS[@]}"; do
  path="$(command -v "$tool" 2>/dev/null || true)"
  if [ -n "$path" ]; then
    state="ON PATH"
    (( on_path++ ))
  else
    stray=""
    for dir in "${SEARCH_DIRS[@]}"; do
      if [ -n "$dir" ] && [ -x "$dir/$tool" ]; then
        stray="$dir/$tool"
        break
      fi
    done
    if [ -n "$stray" ]; then
      state="NOT ON PATH"
      path="$stray"
      (( off_path++ ))
    else
      state="MISSING"
      path="-"
      (( missing++ ))
    fi
  fi

  ver=""
  if [ "$SHOW_VERSIONS" -eq 1 ] && [ "$state" != "MISSING" ]; then
    ver="$("$path" --version 2>/dev/null | head -1 | cut -c1-40)"
    [ -n "$ver" ] || ver="(no --version)"
  fi
  printf '%-22s %-12s %-46s %s\n' "$tool" "$state" "$path" "$ver"
done

echo
echo "on PATH: $on_path   installed but not on PATH: $off_path   missing: $missing"
if [ "$off_path" -gt 0 ]; then
  echo
  echo "The 'NOT ON PATH' tools are installed. The server reaches them only if"
  echo "core.get_enhanced_env() lists their directory - check /health, and run"
  echo "this script as the user the server runs as before reinstalling anything."
fi
