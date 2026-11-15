#!/usr/bin/env bash
# Build the OWASP Dependency-Check NVD cache once, before any scan needs it.
#
# Why this is a separate step
# ---------------------------
# Dependency-Check matches your dependencies against a local copy of the NVD,
# held in an H2 database. Building that copy is a long download, and it is the
# slowest part of a first scan by a wide margin. Two details decide whether it
# takes minutes or hours:
#
#   * The API key. dependencycheck.properties ships
#     nvd.api.requestsperthirtysecondswithoutapikey=5 against
#     nvd.api.requestsperthirtysecondswithapikey=50. Ten times the rate.
#   * Where the cache goes. The shipped default is [JAR]/data, inside
#     /opt/dependency-check, which is root-owned while the server runs as a
#     normal user. A scan there fails before it starts.
#
# So: run this once, as the user the server runs as. Scans then pass
# --noupdate and read the cache, which is what /api/repo-scan already does.
#
# The key is read from the environment or from <repo>/.env, written to a 0600
# property file, and passed with -P. It is never put on a command line, where
# /proc/<pid>/cmdline would expose it to every local account for the length of
# the download, and it is never printed.
#
# Usage:
#   scripts/warm-nvd-cache.sh [--data <dir>] [--force]
#
#   --force   refresh even when the cache looks recent
#
# Expect 10-30 minutes on a first run. Safe to re-run; safe to interrupt.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${DEPENDENCY_CHECK_DATA_DIR:-/var/sast-mcp/depcheck-data}"
FORCE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --data) DATA_DIR="${2:?--data needs a path}"; shift 2 ;;
    --force) FORCE=1; shift ;;
    -h|--help) sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

die() { echo "ERROR: $*" >&2; exit 1; }

# --- the binary, under either of its two names -----------------------------
DC_BIN="${DEPENDENCY_CHECK_PATH:-}"
if [ -z "$DC_BIN" ]; then
  for name in dependency-check.sh dependency-check; do
    if command -v "$name" >/dev/null 2>&1; then
      DC_BIN="$name"
      break
    fi
  done
fi
[ -n "$DC_BIN" ] || die "dependency-check not found. Run tools/install_tools.sh first."
command -v java >/dev/null 2>&1 || die "no JRE on PATH. apt install -y default-jre"

# --- the key, without printing it ------------------------------------------
API_KEY="${NVD_API_KEY:-}"
if [ -z "$API_KEY" ] && [ -f "${REPO_ROOT}/.env" ]; then
  # Read the one line we need rather than sourcing the file, so nothing else
  # in .env gets executed by this script.
  API_KEY="$(grep -m1 -E '^[[:space:]]*NVD_API_KEY[[:space:]]*=' "${REPO_ROOT}/.env" \
    | cut -d= -f2- | tr -d '"'"'"'[:space:]')"
fi
if [ -z "$API_KEY" ]; then
  cat >&2 <<'MSG'
ERROR: no NVD API key.

Put it in <repo>/.env as:

    NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

Request one at https://nvd.nist.gov/developers/request-an-api-key

Without a key the NVD allows 5 requests per 30 seconds instead of 50, which
turns this from minutes into hours. .env is gitignored; keep the key there and
nowhere else.
MSG
  exit 1
fi
echo "NVD API key: found (${#API_KEY} characters)"

# --- the cache directory ---------------------------------------------------
mkdir -p "$DATA_DIR" 2>/dev/null || die "cannot create $DATA_DIR as $(id -un)"
[ -w "$DATA_DIR" ] || die "$DATA_DIR is not writable by $(id -un)"
echo "cache dir   : $DATA_DIR"

existing="$(find "$DATA_DIR" -type f -name '*.db' 2>/dev/null | head -1)"
if [ -n "$existing" ] && [ "$FORCE" -eq 0 ]; then
  age_h=$(( ( $(date +%s) - $(stat -c %Y "$existing") ) / 3600 ))
  echo "cache exists, last updated ${age_h}h ago."
  if [ "$age_h" -lt 24 ]; then
    echo "Less than 24h old; nothing to do. Use --force to refresh anyway."
    exit 0
  fi
  echo "Older than 24h; refreshing."
fi

# --- the key goes in a private file, not in argv ---------------------------
PROPS="$(mktemp -t dc-nvd-XXXXXX.properties)" || die "mktemp failed"
chmod 600 "$PROPS"
cleanup() { rm -f "$PROPS"; }
trap cleanup EXIT INT TERM
printf 'nvd.api.key=%s\n' "$API_KEY" > "$PROPS"

echo
echo "Updating the NVD cache. This is a long download; 10-30 minutes is normal."
echo "Started at $(date '+%H:%M:%S'). Safe to interrupt and re-run."
echo

START=$(date +%s)
"$DC_BIN" --updateonly -P "$PROPS" --data "$DATA_DIR" --disableVersionCheck
rc=$?
ELAPSED=$(( $(date +%s) - START ))

echo
if [ "$rc" -ne 0 ]; then
  echo "FAILED after ${ELAPSED}s (exit $rc)."
  echo "A 403 or 404 from the NVD usually means the key is wrong or not yet active."
  echo "Re-running is safe: the download resumes rather than starting over."
  exit "$rc"
fi

SIZE="$(du -sh "$DATA_DIR" 2>/dev/null | cut -f1)"
echo "Done in ${ELAPSED}s. Cache is ${SIZE:-unknown} in $DATA_DIR."
echo
echo "Check the server agrees:"
echo "  curl -s localhost:6000/health | python3 -m json.tool | grep -A8 dependency_check"
echo
echo "Scans pass --noupdate and read this cache, so they no longer touch the network."
echo "Refresh it when it ages; 24h+ is the point where a re-run does real work."
