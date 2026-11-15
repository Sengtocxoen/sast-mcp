#!/usr/bin/env bash
# Install the Python-based scanners so they survive a server venv rebuild.
#
# Why this exists
# ---------------
# semgrep, checkov and safety used to be pip-installed into the server's own
# virtualenv (<repo>/venv). core.get_enhanced_env() puts that venv's bin dir on
# the executor PATH, so it worked -- until the venv was recreated for Python
# 3.14. The rebuild deleted all three. /health reported them missing, scans kept
# returning success with those engines simply absent, and a stale
# ~/.local/bin/semgrep symlink pointed into the deleted venv, so the binary
# still showed up in `ls` while `which semgrep` found nothing.
#
# pipx gives each tool its own venv under ~/.local/share/pipx/venvs, which is
# independent of the server venv and of the interpreter the server runs on.
#
# Safe to re-run: installs what is missing, upgrades what is present.

set -euo pipefail

TOOLS=(semgrep checkov safety)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_BIN="${REPO_ROOT}/venv/bin"

if ! command -v pipx >/dev/null 2>&1; then
  echo "pipx is not installed. Install it first, then re-run:" >&2
  echo "  sudo apt install pipx   # or: python3 -m pip install --user pipx" >&2
  exit 1
fi

# pipx's own bin dir, rather than assuming ~/.local/bin.
PIPX_BIN_DIR="$(pipx environment --value PIPX_BIN_DIR 2>/dev/null || true)"
PIPX_BIN_DIR="${PIPX_BIN_DIR:-${HOME}/.local/bin}"
echo "pipx bin dir: ${PIPX_BIN_DIR}"

# A symlink in the pipx bin dir pointing into the server venv is already broken,
# or will break on the next rebuild. Clear it so pipx can own the name.
for tool in "${TOOLS[@]}"; do
  link="${PIPX_BIN_DIR}/${tool}"
  if [ -L "$link" ]; then
    target="$(readlink -f "$link" || true)"
    if [ -z "$target" ] || [ ! -e "$target" ] || [[ "$target" == "$VENV_BIN"/* ]]; then
      echo "removing stale symlink: $link -> ${target:-<dangling>}"
      rm -f "$link"
    fi
  fi
done

# `pipx upgrade` is a no-op when the package is already at the latest version,
# and a no-op does NOT re-create a missing app symlink. Combined with the
# stale-link removal above, that left pipx reporting "semgrep is already at
# latest version" on every run while nothing was ever linked into
# ${PIPX_BIN_DIR} - so the tool stayed invisible to PATH, to /health and to
# scans. When the package is present but its link is not, force a reinstall.
for tool in "${TOOLS[@]}"; do
  link="${PIPX_BIN_DIR}/${tool}"
  if pipx list --short 2>/dev/null | awk '{print $1}' | grep -qx "$tool"; then
    if [ -x "$link" ]; then
      echo "== upgrading $tool"
      pipx upgrade "$tool" || true
    else
      echo "== reinstalling $tool (pipx has the package, but ${link} is missing)"
      pipx install --force "$tool"
    fi
  else
    echo "== installing $tool"
    pipx install "$tool"
  fi
done

# Make the bin dir reachable from the invoking user's interactive shells. This
# does not affect sudo (secure_path) or the server, which gets the directory
# from core.get_enhanced_env().
pipx ensurepath >/dev/null 2>&1 || true

echo
echo "== verification"
status=0
for tool in "${TOOLS[@]}"; do
  path="$(command -v "$tool" || true)"
  if [ -z "$path" ] && [ -x "${PIPX_BIN_DIR}/${tool}" ]; then
    # Running under sudo, PATH is sudo's secure_path and will not contain the
    # pipx bin dir. The tool is installed; reporting FAIL here is what made the
    # installer announce three working scanners as broken.
    echo "warn  ${tool}: installed at ${PIPX_BIN_DIR}/${tool}, which is not on this shell's PATH"
    path="${PIPX_BIN_DIR}/${tool}"
  fi
  if [ -z "$path" ]; then
    echo "FAIL  ${tool}: not installed (no ${PIPX_BIN_DIR}/${tool}, not on PATH)"
    status=1
    continue
  fi
  real="$(readlink -f "$path")"
  if [[ "$real" == "$VENV_BIN"/* ]]; then
    echo "FAIL  ${tool}: resolves into the server venv (${real}); it will be lost on rebuild"
    status=1
    continue
  fi
  printf 'ok    %-9s %s\n' "$tool" "$real"
done

if [ "$status" -ne 0 ]; then
  echo
  echo "One or more scanners are not installed durably. See the notes at the top of this script." >&2
  exit 1
fi

echo
echo "All scanners resolve outside the server venv. Check /health for fragile_tools."
