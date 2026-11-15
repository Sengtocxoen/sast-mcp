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

# A symlink in ~/.local/bin pointing into the server venv is already broken, or
# will break on the next rebuild. Clear it so pipx can own the name.
for tool in "${TOOLS[@]}"; do
  link="${HOME}/.local/bin/${tool}"
  if [ -L "$link" ]; then
    target="$(readlink -f "$link" || true)"
    if [ -z "$target" ] || [ ! -e "$target" ] || [[ "$target" == "$VENV_BIN"/* ]]; then
      echo "removing stale symlink: $link -> ${target:-<dangling>}"
      rm -f "$link"
    fi
  fi
done

for tool in "${TOOLS[@]}"; do
  if pipx list --short 2>/dev/null | awk '{print $1}' | grep -qx "$tool"; then
    echo "== upgrading $tool"
    pipx upgrade "$tool" || true
  else
    echo "== installing $tool"
    pipx install "$tool"
  fi
done

echo
echo "== verification"
status=0
for tool in "${TOOLS[@]}"; do
  path="$(command -v "$tool" || true)"
  if [ -z "$path" ]; then
    echo "FAIL  ${tool}: not on PATH"
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
