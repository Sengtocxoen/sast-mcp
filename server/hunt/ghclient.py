"""
ghclient.py - the one HTTP client every hunt tool shares.

Why this exists instead of shelling out to curl: each gate in the hunt pipeline
is a metadata lookup, and a curl per gate per repo costs a process spawn before
any analysis happens - five gates across the 297-repo catalog is ~1,500 forks.
One pooled session with an on-disk cache turns that into a few hundred
keep-alive requests, nearly all of them served from disk on a re-run.

Three things this has to get right, each a trap recorded in
docs/hunt-pipeline/ARCHITECTURE.md:

* **The unauthenticated API ceiling is 60 requests/hour**, fewer than one
  request per catalog repo ("gate by category, not all 297 at once", section 6).
  So the budget is read from x-ratelimit-remaining and RateLimited is raised
  BEFORE issuing the request that would fail - gating stops cleanly with partial
  results and a resume point instead of melting into a wall of 403s. Export
  GITHUB_TOKEN to get 5,000/hour.
* **raw.githubusercontent.com is not metered by the API**, and G2 (is this
  project already in OSS-Fuzz?) is a raw fetch. Keeping the two hosts on
  separate accounting is what makes G2 effectively free, so api() and raw() are
  separate methods and only api() spends budget.
* **404 is an answer, not a failure.** G2 reads 404 on project.yaml as "nobody
  is fuzzing this". A missing document is cached and returned like any other
  response; only transport errors raise.

The transport is injectable, so every gate is testable against recorded fixtures
with no network - the same rule the pipeline applies to itself: prove the tool
works on a known input before believing what it says about a new one.
"""
import hashlib
import json
import logging
import os
import re
import tempfile
import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

API_HOST = "https://api.github.com"
RAW_HOST = "https://raw.githubusercontent.com"

# The only hosts this client will talk to. Both api() and raw() accept an
# absolute URL for convenience, and a catalog URL can come from a request body,
# so without this allowlist a caller could point the client at any host - which
# would both SSRF the server (link-local metadata, localhost admin ports) and
# hand GITHUB_TOKEN to whoever answers, since the Authorization header was
# attached by token presence rather than by destination. Enforced here, at the
# single choke point every hunt module fetches through, rather than in each
# caller.
ALLOWED_HOSTS = frozenset({"api.github.com", "raw.githubusercontent.com"})

# Cache lifetimes in seconds. A last-commit date and an open-PR list both move,
# but not within one gating run; the OSS-Fuzz project list barely moves at all.
TTL_COMMIT = int(os.environ.get("HUNT_TTL_COMMIT", 6 * 3600))
TTL_PULLS = int(os.environ.get("HUNT_TTL_PULLS", 3600))
TTL_OSSFUZZ = int(os.environ.get("HUNT_TTL_OSSFUZZ", 24 * 3600))
TTL_POLICY = int(os.environ.get("HUNT_TTL_POLICY", 24 * 3600))

# Stop this many requests short of the ceiling, so the caller can finish the repo
# it is in the middle of rather than failing partway through one.
DEFAULT_RESERVE = int(os.environ.get("HUNT_RATE_RESERVE", 2))

# A transport is (method, url, headers, timeout) -> (status, body, headers).
Transport = Callable[[str, str, Dict[str, str], float], Tuple[int, str, Dict[str, str]]]


class RateLimited(RuntimeError):
    """Raised before a request the remaining API budget cannot pay for."""

    def __init__(self, remaining: int, reset_at: int, url: str = ""):
        self.remaining = remaining
        self.reset_at = reset_at
        self.url = url
        wait = max(0, int(reset_at - time.time())) if reset_at else 0
        super().__init__(
            f"GitHub API budget exhausted (remaining={remaining}, resets in {wait}s). "
            f"Set GITHUB_TOKEN for 5,000 req/hour, or resume after the reset."
        )


class TransportError(RuntimeError):
    """The request never produced an HTTP status (DNS, TLS, timeout, reset)."""


class UntrustedHost(ValueError):
    """The URL points somewhere this client will not send a GitHub token."""


# Any scheme, any case. A case-sensitive startswith("http") would treat
# "HTTPS://evil.example/x" as a relative path and quietly prefix it onto the
# trusted host instead of rejecting it, and would let "file://" through the same
# way. Detect the scheme properly, then let the allowlist decide.
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.I)


def is_absolute_url(value: str) -> bool:
    return bool(_SCHEME_RE.match(value or ""))


def assert_allowed_url(url: str) -> str:
    """Return the hostname, or raise if it is not a host we fetch from.

    urlparse is used rather than a prefix check on purpose: it resolves the
    userinfo trick ("https://api.github.com@evil.example/") to the real host,
    which a startswith() on API_HOST would wave straight through.
    """
    parsed = urlparse(url or "")
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or host not in ALLOWED_HOSTS:
        raise UntrustedHost(
            f"refusing to fetch {str(url)[:120]!r}: only https to "
            f"{', '.join(sorted(ALLOWED_HOSTS))} is allowed"
        )
    return host


class Response:
    __slots__ = ("status", "body", "headers", "from_cache", "url")

    def __init__(self, status: int, body: str, headers: Dict[str, str],
                 url: str = "", from_cache: bool = False):
        self.status = status
        self.body = body
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.url = url
        self.from_cache = from_cache

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self, default: Any = None) -> Any:
        """Parsed body, or `default` when absent/unparseable. Never raises."""
        if not self.body:
            return default
        try:
            return json.loads(self.body)
        except (ValueError, TypeError):
            return default

    def __repr__(self) -> str:
        tail = " cached" if self.from_cache else ""
        return f"<Response {self.status} {self.url}{tail}>"


class DiskCache:
    """URL -> response on disk, so re-gating a catalog costs almost nothing.

    Keyed by a hash of the URL rather than the URL itself, because raw paths
    contain slashes and arbitrary repo names. Writes go through a temp file and
    os.replace, so a crashed run cannot leave a half-written entry that poisons
    the next one.
    """

    def __init__(self, directory: Optional[str] = None):
        self.dir = directory or os.environ.get("HUNT_CACHE_DIR") or os.path.join(
            tempfile.gettempdir(), "sast-mcp-hunt-cache")
        self._lock = threading.Lock()
        try:
            os.makedirs(self.dir, exist_ok=True)
            self.enabled = True
        except OSError as e:
            # A read-only or missing cache dir must not take the tools down.
            logger.warning("hunt cache disabled (%s): %s", self.dir, e)
            self.enabled = False

    def _path(self, url: str) -> str:
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
        return os.path.join(self.dir, digest + ".json")

    def get(self, url: str) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        try:
            with open(self._path(url), "r", encoding="utf-8") as f:
                entry = json.load(f)
            return entry if isinstance(entry, dict) else None
        except (OSError, ValueError):
            return None

    def put(self, url: str, status: int, body: str, headers: Dict[str, str]) -> None:
        if not self.enabled:
            return
        entry = {
            "status": status,
            "body": body,
            "headers": {k.lower(): v for k, v in (headers or {}).items()},
            "fetched_at": time.time(),
        }
        try:
            with self._lock:
                fd, tmp = tempfile.mkstemp(dir=self.dir, suffix=".tmp")
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as f:
                        json.dump(entry, f)
                    os.replace(tmp, self._path(url))
                except BaseException:
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
                    raise
        except OSError as e:
            logger.debug("cache write failed for %s: %s", url, e)

    def clear(self) -> int:
        if not self.enabled:
            return 0
        removed = 0
        for name in os.listdir(self.dir):
            if not name.endswith(".json"):
                continue
            try:
                os.unlink(os.path.join(self.dir, name))
                removed += 1
            except OSError:
                pass
        return removed


def _requests_transport(pool_size: int = 16) -> Transport:
    """Default transport: one pooled requests.Session that retries 5xx.

    Imported lazily so this module stays importable (and testable) in an
    environment without requests installed.
    """
    import requests
    from requests.adapters import HTTPAdapter

    retry: Any = None
    try:
        from urllib3.util.retry import Retry
        retry = Retry(
            total=2, connect=2, read=2, backoff_factor=0.5,
            status_forcelist=(500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD"]),
            raise_on_status=False,
        )
    except Exception:  # pragma: no cover - ancient urllib3
        retry = None

    session = requests.Session()
    adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size,
                          max_retries=retry)
    session.mount("https://", adapter)

    def transport(method: str, url: str, headers: Dict[str, str], timeout: float):
        try:
            r = session.request(method, url, headers=headers, timeout=timeout)
        except Exception as e:
            raise TransportError(f"{type(e).__name__}: {e}") from e
        return r.status_code, r.text, dict(r.headers)

    return transport


class GitHubClient:
    """Pooled, cached, rate-limit-aware access to the two hosts gating needs."""

    def __init__(self, token: Optional[str] = None, transport: Optional[Transport] = None,
                 cache: Optional[DiskCache] = None, timeout: float = 12.0,
                 reserve: int = DEFAULT_RESERVE, pool_size: int = 16,
                 use_cache: bool = True):
        self.token = token if token is not None else (
            os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "")
        self._transport = transport or _requests_transport(pool_size)
        self.cache = cache if cache is not None else (DiskCache() if use_cache else None)
        self.timeout = timeout
        self.reserve = reserve
        self._lock = threading.Lock()
        # Unknown until the first metered response says otherwise. -1 means "not
        # yet probed", deliberately distinct from 0 ("spent").
        self.remaining = -1
        self.limit = -1
        self.reset_at = 0
        self.api_requests = 0
        self.raw_requests = 0
        self.cache_hits = 0

    # -- budget ---------------------------------------------------------------

    def budget(self) -> Dict[str, Any]:
        """What is left, for honest partial-result reporting."""
        with self._lock:
            reset_in = max(0, int(self.reset_at - time.time())) if self.reset_at else 0
            known = self.remaining >= 0
            return {
                "authenticated": bool(self.token),
                "limit": self.limit,
                "remaining": self.remaining,
                # -1 on its own reads like a failure. It means no metered request
                # has happened yet in this process - usually because everything
                # was served from the cache, which is the good case.
                "remaining_known": known,
                "status": ("%d of %d left, resets in %ds" % (self.remaining, self.limit, reset_in)
                           if known else
                           "not yet probed (no metered request made; cache served everything)"),
                "reset_at": self.reset_at,
                "reset_in_seconds": reset_in,
                "api_requests_made": self.api_requests,
                "raw_requests_made": self.raw_requests,
                "cache_hits": self.cache_hits,
                "reserve": self.reserve,
            }

    def _note_limits(self, headers: Dict[str, str]) -> None:
        with self._lock:
            for key, attr in (("x-ratelimit-remaining", "remaining"),
                              ("x-ratelimit-limit", "limit"),
                              ("x-ratelimit-reset", "reset_at")):
                raw = headers.get(key)
                if raw is None:
                    continue
                try:
                    setattr(self, attr, int(raw))
                except (TypeError, ValueError):
                    pass

    def _assert_budget(self, url: str) -> None:
        with self._lock:
            remaining, reset_at = self.remaining, self.reset_at
        if remaining < 0:
            return  # not yet probed: spend one request to find out
        if remaining > self.reserve:
            return
        if reset_at and time.time() >= reset_at:
            with self._lock:
                self.remaining = -1  # window rolled over; re-probe
            return
        raise RateLimited(remaining, reset_at, url)

    # -- fetching -------------------------------------------------------------

    def _headers(self, metered: bool, host: str) -> Dict[str, str]:
        h = {"User-Agent": "sast-mcp-hunt/1.0", "Accept-Encoding": "gzip"}
        if metered:
            h["Accept"] = "application/vnd.github+json"
            h["X-GitHub-Api-Version"] = "2022-11-28"
        # Keyed on the destination, not merely on having a token: credentials go
        # to GitHub or nowhere.
        if self.token and host in ALLOWED_HOSTS:
            h["Authorization"] = f"Bearer {self.token}"
        return h

    def _fetch(self, url: str, ttl: int, metered: bool, refresh: bool = False) -> Response:
        host = assert_allowed_url(url)
        if self.cache is not None and not refresh and ttl > 0:
            entry = self.cache.get(url)
            if entry and (time.time() - entry.get("fetched_at", 0)) < ttl:
                with self._lock:
                    self.cache_hits += 1
                return Response(entry.get("status", 0), entry.get("body", ""),
                                entry.get("headers", {}), url, from_cache=True)

        if metered:
            self._assert_budget(url)

        status, body, headers = self._transport("GET", url, self._headers(metered, host),
                                                self.timeout)
        # Normalise case HERE, before anything reads a header. GitHub sends
        # 'X-RateLimit-Remaining'; matching only the lowercase spelling meant the
        # budget was never actually tracked against the live API, so the 60/hour
        # ceiling protection silently did nothing.
        headers = {k.lower(): v for k, v in (headers or {}).items()}
        with self._lock:
            if metered:
                self.api_requests += 1
            else:
                self.raw_requests += 1

        if metered:
            self._note_limits(headers)
            # A 403/429 with nothing left is the ceiling, not a permission problem.
            spent = str(headers.get("x-ratelimit-remaining", "")).strip() == "0"
            if status in (403, 429) and spent:
                raise RateLimited(0, self.reset_at, url)

        # 404s are cached too: "no OSS-Fuzz project" and "no SECURITY.md" are both
        # real answers that should not be re-fetched 60 times in one run.
        if self.cache is not None and ttl > 0 and status in (200, 301, 404, 410):
            self.cache.put(url, status, body, headers)
        return Response(status, body, headers, url)

    def api(self, path: str, ttl: int = TTL_COMMIT, refresh: bool = False) -> Response:
        """A metered api.github.com GET. Spends budget; may raise RateLimited."""
        url = path if is_absolute_url(path) else f"{API_HOST}/{str(path).lstrip('/')}"
        return self._fetch(url, ttl, metered=True, refresh=refresh)

    def raw(self, path: str, ttl: int = TTL_OSSFUZZ, refresh: bool = False) -> Response:
        """An unmetered raw.githubusercontent.com GET. Free; 404 is an answer."""
        url = path if is_absolute_url(path) else f"{RAW_HOST}/{str(path).lstrip('/')}"
        return self._fetch(url, ttl, metered=False, refresh=refresh)
