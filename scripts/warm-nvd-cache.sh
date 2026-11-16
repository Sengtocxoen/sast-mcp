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
# Two upstream failures this script handles, both seen on 2026-11-15
# ------------------------------------------------------------------
# 1. The NVD API returns 503 in bursts, and dependency-check retries without
#    backoff (upstream issues #8469, #8618, #6107), so 31 retries can burn in
#    14 seconds and the update fails. A 503 is NOT a key problem. This script
#    probes the API first, sets an explicit --nvdApiDelay, and retries the
#    whole update with widening gaps.
# 2. www.cisa.gov returns 403 for the Known Exploited Vulnerabilities feed from
#    some networks, and that failure aborts the whole update even though the
#    NVD part is unrelated. The feed is probed up front; when it is blocked,
#    the KEV analyzer is disabled for this run so the NVD download can finish.
#    Point --kev-url at a mirror you control to keep the enrichment.
#
# Usage:
#   scripts/warm-nvd-cache.sh [options]
#
#   --data <dir>      cache directory (default $DEPENDENCY_CHECK_DATA_DIR)
#   --force           refresh even when the cache looks recent
#   --attempts <n>    whole-update attempts on a 503 (default 3)
#   --delay <ms>      --nvdApiDelay value (default 6000)
#   --retries <n>     --nvdMaxRetryCount value (default 30)
#   --kev-url <url>   mirror for the CISA KEV feed instead of disabling it
#   --no-kev          always disable the KEV analyzer
#   --skip-probe      do not pre-flight the NVD API
#
# Expect 10-30 minutes on a first run. Safe to re-run; safe to interrupt.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${DEPENDENCY_CHECK_DATA_DIR:-/var/sast-mcp/depcheck-data}"
FORCE=0
ATTEMPTS="${NVD_WARM_ATTEMPTS:-3}"
API_DELAY_MS="${NVD_API_DELAY_MS:-6000}"
MAX_RETRY="${NVD_MAX_RETRY_COUNT:-30}"
KEV_URL=""
NO_KEV=0
SKIP_PROBE=0
NVD_PROBE_URL="https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"
KEV_FEED_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

while [ $# -gt 0 ]; do
  case "$1" in
    --data) DATA_DIR="${2:?--data needs a path}"; shift 2 ;;
    --force) FORCE=1; shift ;;
    --attempts) ATTEMPTS="${2:?--attempts needs a number}"; shift 2 ;;
    --delay) API_DELAY_MS="${2:?--delay needs milliseconds}"; shift 2 ;;
    --retries) MAX_RETRY="${2:?--retries needs a number}"; shift 2 ;;
    --kev-url) KEV_URL="${2:?--kev-url needs a URL}"; shift 2 ;;
    --no-kev) NO_KEV=1; shift ;;
    --skip-probe) SKIP_PROBE=1; shift ;;
    -h|--help) sed -n '2,56p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
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
command -v curl >/dev/null 2>&1 || SKIP_PROBE=1

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
CURL_CFG="$(mktemp -t dc-curl-XXXXXX.conf)" || die "mktemp failed"
chmod 600 "$CURL_CFG"
cleanup() { rm -f "$PROPS" "$CURL_CFG"; }
trap cleanup EXIT INT TERM
printf 'nvd.api.key=%s\n' "$API_KEY" > "$PROPS"
# curl reads the header from this file, so the key stays out of argv here too.
printf 'header = "apiKey: %s"\nsilent\n' "$API_KEY" > "$CURL_CFG"

http_status() {
  # http_status <url> [--authed]
  local url="$1" authed="${2:-}"
  if [ "$authed" = "--authed" ]; then
    curl --config "$CURL_CFG" -o /dev/null -w '%{http_code}' --max-time 45 "$url" 2>/dev/null
  else
    curl -s -o /dev/null -w '%{http_code}' --max-time 45 "$url" 2>/dev/null
  fi
}

# --- pre-flight: is this the key, the NVD, or the network? -----------------
if [ "$SKIP_PROBE" -eq 0 ]; then
  echo
  echo "Checking the NVD API before starting the long download..."
  status="$(http_status "$NVD_PROBE_URL" --authed)"
  case "$status" in
    200)
      echo "  NVD API: 200 OK, the key is accepted." ;;
    401|403)
      echo "  NVD API: $status." >&2
      cat >&2 <<'MSG'

The key was rejected. A new key must be activated from the link in the email
the NVD sends; until then it returns 403. Check the value in .env for stray
spaces or quotes, then re-run.
MSG
      exit 1 ;;
    404)
      echo "  NVD API: 404. The endpoint or the key is wrong; check .env." >&2
      exit 1 ;;
    503)
      cat >&2 <<'MSG'
  NVD API: 503 Service Unavailable.

This is the NVD, not your key and not this server. The API returns 503 in
bursts, and dependency-check retries without backoff (upstream issues #8469,
#8618, #6107), so an update can fail in seconds. This script will still try,
with a wider delay and several attempts, but if every attempt gets 503 the
answer is to wait and re-run later.
MSG
      ;;
    000)
      echo "  NVD API: no response (timeout or DNS). Check egress from this host." >&2
      exit 1 ;;
    *)
      echo "  NVD API: HTTP $status. Continuing anyway." ;;
  esac
fi

# --- pre-flight: the CISA KEV feed is a separate data source ---------------
KEV_ARGS=""
if [ "$NO_KEV" -eq 1 ]; then
  KEV_ARGS="--disableKnownExploited"
  echo "KEV feed    : disabled by --no-kev."
elif [ -n "$KEV_URL" ]; then
  KEV_ARGS="--kevURL $KEV_URL"
  echo "KEV feed    : using mirror $KEV_URL"
elif [ "$SKIP_PROBE" -eq 0 ]; then
  kev_status="$(http_status "$KEV_FEED_URL")"
  if [ "$kev_status" = "200" ]; then
    echo "KEV feed    : 200 OK."
  else
    KEV_ARGS="--disableKnownExploited"
    echo "KEV feed    : HTTP $kev_status from www.cisa.gov, so the Known Exploited"
    echo "              Vulnerabilities analyzer is disabled for this run."
    echo "              Otherwise that one 403 aborts the whole NVD update."
    echo "              Findings will not carry the 'known exploited' flag."
    echo "              To keep it, mirror the feed and pass --kev-url <url>."
  fi
fi

echo
echo "Updating the NVD cache. This is a long download; 10-30 minutes is normal."
echo "Delay between API calls: ${API_DELAY_MS}ms, max ${MAX_RETRY} retries per call."
echo "Started at $(date '+%H:%M:%S'). Safe to interrupt and re-run."
echo

START=$(date +%s)
rc=1
attempt=1
while [ "$attempt" -le "$ATTEMPTS" ]; do
  if [ "$attempt" -gt 1 ]; then
    # NVD_WARM_BACKOFF_SECS exists so the retry loop can be tested without
    # waiting minutes; leave it unset in normal use.
    backoff=$(( (attempt - 1) * ${NVD_WARM_BACKOFF_SECS:-120} ))
    echo
    echo "Attempt $attempt of $ATTEMPTS in ${backoff}s. Downloaded pages are kept,"
    echo "so a re-run resumes rather than starting over."
    sleep "$backoff"
  fi
  # shellcheck disable=SC2086 -- KEV_ARGS is a deliberate word split
  "$DC_BIN" --updateonly -P "$PROPS" --data "$DATA_DIR" --disableVersionCheck \
    --nvdApiDelay "$API_DELAY_MS" --nvdMaxRetryCount "$MAX_RETRY" $KEV_ARGS
  rc=$?
  [ "$rc" -eq 0 ] && break
  echo "Attempt $attempt failed (exit $rc)."
  attempt=$(( attempt + 1 ))
done
ELAPSED=$(( $(date +%s) - START ))

echo
if [ "$rc" -ne 0 ]; then
  echo "FAILED after ${ELAPSED}s and $((attempt - 1)) attempt(s) (exit $rc)."
  echo
  echo "Read the stack trace above for which data source failed:"
  echo "  NvdApiException / 'NVD Returned Status Code: 503'"
  echo "      the NVD is unavailable. Not your key. Wait and re-run."
  echo "  ForbiddenException on www.cisa.gov"
  echo "      the KEV feed is blocked here. Re-run with --no-kev, or mirror the"
  echo "      feed and pass --kev-url."
  echo "  401/403 from services.nvd.nist.gov"
  echo "      the key is wrong or not activated yet."
  echo
  echo "Nothing is corrupted by a failed update; the cache is only replaced on"
  echo "a successful one."
  exit "$rc"
fi

SIZE="$(du -sh "$DATA_DIR" 2>/dev/null | cut -f1)"
echo "Done in ${ELAPSED}s. Cache is ${SIZE:-unknown} in $DATA_DIR."
if [ -n "$KEV_ARGS" ] && [ "$KEV_ARGS" = "--disableKnownExploited" ]; then
  echo "Note: built without the CISA KEV enrichment (see above)."
fi
echo
echo "Check the server agrees:"
echo "  curl -s localhost:6000/health | python3 -m json.tool | grep -A8 dependency_check"
echo
echo "Scans pass --noupdate and read this cache, so they no longer touch the network."
echo "Refresh it when it ages; 24h+ is the point where a re-run does real work."
