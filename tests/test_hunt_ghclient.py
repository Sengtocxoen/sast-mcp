"""
Client tests: budget tracking, caching, and the two hosts' separate accounting.

The casing test exists because of a real escape. Every fake transport in the
other suites returned lowercase header names, so the budget tracking passed its
tests while never working against GitHub, which sends 'X-RateLimit-Remaining'.
The ceiling protection was dead in production and green in CI. These fakes now
use the real casing.
"""
import os
import sys
import time
from urllib.parse import urlparse

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server"))

from hunt.ghclient import (  # noqa: E402
    DiskCache, GitHubClient, RateLimited, Response, TransportError, UntrustedHost)

# Exactly as api.github.com spells them.
REAL_CASING = {
    "X-RateLimit-Limit": "60",
    "X-RateLimit-Remaining": "7",
    "X-RateLimit-Used": "53",
    "X-RateLimit-Reset": str(int(time.time()) + 1800),
    "Content-Type": "application/json; charset=utf-8",
}


def transport_returning(status=200, body="{}", headers=None, record=None):
    def t(method, url, hdrs, timeout):
        if record is not None:
            record.append(url)
        return status, body, dict(headers if headers is not None else REAL_CASING)
    return t


def test_budget_is_tracked_from_real_world_header_casing():
    c = GitHubClient(token="", transport=transport_returning(), cache=None, use_cache=False)
    c.api("/repos/o/r")
    b = c.budget()
    assert b["remaining"] == 7, "header casing regression: budget not tracked"
    assert b["limit"] == 60
    assert b["api_requests_made"] == 1


def test_client_refuses_the_request_that_would_breach_the_ceiling():
    spent = dict(REAL_CASING, **{"X-RateLimit-Remaining": "1"})
    c = GitHubClient(token="", transport=transport_returning(headers=spent),
                     cache=None, use_cache=False, reserve=2)
    c.api("/repos/o/r")              # learns remaining=1
    with pytest.raises(RateLimited) as e:
        c.api("/repos/o/r2")         # must not be sent
    assert "GITHUB_TOKEN" in str(e.value)


def test_raw_requests_never_spend_api_budget():
    calls = []
    c = GitHubClient(token="", transport=transport_returning(record=calls),
                     cache=None, use_cache=False)
    c.raw("google/oss-fuzz/master/projects/stb/project.yaml")
    b = c.budget()
    assert b["api_requests_made"] == 0
    assert b["raw_requests_made"] == 1
    assert "raw.githubusercontent.com" in calls[0]


def test_404_is_returned_as_an_answer_not_raised():
    c = GitHubClient(token="", transport=transport_returning(status=404, body=""),
                     cache=None, use_cache=False)
    r = c.raw("google/oss-fuzz/master/projects/nope/project.yaml")
    assert r.status == 404
    assert r.ok is False


def test_403_with_nothing_left_is_the_ceiling_not_a_permission_error():
    spent = dict(REAL_CASING, **{"X-RateLimit-Remaining": "0"})
    c = GitHubClient(token="", transport=transport_returning(status=403, body="", headers=spent),
                     cache=None, use_cache=False)
    with pytest.raises(RateLimited):
        c.api("/repos/o/r")


def test_window_rollover_lets_requests_through_again():
    expired = dict(REAL_CASING, **{"X-RateLimit-Remaining": "0",
                                   "X-RateLimit-Reset": str(int(time.time()) - 10)})
    c = GitHubClient(token="", transport=transport_returning(headers=expired),
                     cache=None, use_cache=False)
    c.api("/repos/o/r")
    c.api("/repos/o/r2")  # reset time has passed: must re-probe, not raise
    assert c.budget()["api_requests_made"] == 2


def test_transport_errors_propagate_rather_than_look_like_a_404():
    def boom(method, url, hdrs, timeout):
        raise TransportError("ConnectionError: refused")
    c = GitHubClient(token="", transport=boom, cache=None, use_cache=False)
    with pytest.raises(TransportError):
        c.api("/repos/o/r")


def test_token_is_sent_as_a_bearer_header():
    seen = {}

    def t(method, url, hdrs, timeout):
        seen.update(hdrs)
        return 200, "{}", dict(REAL_CASING)

    GitHubClient(token="ghp_example", transport=t, cache=None, use_cache=False).api("/x")
    assert seen["Authorization"] == "Bearer ghp_example"


def test_cache_serves_the_second_call_without_a_request(tmp_path):
    calls = []
    cache = DiskCache(str(tmp_path))
    c = GitHubClient(token="", transport=transport_returning(record=calls), cache=cache)
    c.api("/repos/o/r", ttl=600)
    c.api("/repos/o/r", ttl=600)
    assert len(calls) == 1, "second call should have been served from disk"
    assert c.budget()["cache_hits"] == 1


def test_cache_refresh_forces_a_new_request(tmp_path):
    calls = []
    cache = DiskCache(str(tmp_path))
    c = GitHubClient(token="", transport=transport_returning(record=calls), cache=cache)
    c.api("/repos/o/r", ttl=600)
    c.api("/repos/o/r", ttl=600, refresh=True)
    assert len(calls) == 2


def test_expired_cache_entry_is_refetched(tmp_path):
    calls = []
    cache = DiskCache(str(tmp_path))
    c = GitHubClient(token="", transport=transport_returning(record=calls), cache=cache)
    c.api("/repos/o/r", ttl=0)
    c.api("/repos/o/r", ttl=0)
    assert len(calls) == 2


def test_cache_survives_a_corrupt_entry(tmp_path):
    cache = DiskCache(str(tmp_path))
    cache.put("https://api.github.com/x", 200, "{}", {})
    path = cache._path("https://api.github.com/x")
    with open(path, "w") as f:
        f.write("{not json")
    assert cache.get("https://api.github.com/x") is None


def test_cache_disabled_when_directory_is_unusable(tmp_path):
    blocker = tmp_path / "afile"
    blocker.write_text("x")
    cache = DiskCache(str(blocker / "sub"))
    assert cache.enabled is False
    assert cache.get("https://x") is None  # must not raise


def test_response_json_never_raises_on_garbage():
    assert Response(200, "<html>not json</html>", {}).json("fallback") == "fallback"
    assert Response(404, "", {}).json() is None


# -- host allowlist: no token, and no request, to anywhere but GitHub -------

@pytest.mark.parametrize("url", [
    "https://evil.example/collect",
    "http://api.github.com/repos/o/r",                 # plaintext
    "https://api.github.com@evil.example/repos/o/r",   # userinfo trick
    "https://raw.githubusercontent.com.evil.example/x",
    "https://169.254.169.254/latest/meta-data/",       # cloud metadata
    "http://127.0.0.1:6077/api/hunt",                  # back at ourselves
    "https://[::1]/admin",
    "HTTPS://EVIL.EXAMPLE/x",                          # case
])
def test_untrusted_hosts_are_refused_before_any_request(url):
    """A catalog URL arrives in a request body, so this is reachable input."""
    calls = []
    c = GitHubClient(token="ghp_secret", transport=transport_returning(record=calls),
                     cache=None, use_cache=False)
    with pytest.raises(UntrustedHost):
        c.raw(url)
    with pytest.raises(UntrustedHost):
        c.api(url)
    assert calls == [], "a request was issued to an untrusted host"


def test_the_token_never_leaves_for_a_non_github_host():
    """The exact leak: Authorization was attached by token presence, not by
    destination, so one POST exfiltrated GITHUB_TOKEN to any host."""
    seen = []

    def t(method, url, hdrs, timeout):
        seen.append(hdrs.get("Authorization", "<none>"))
        return 200, "{}", dict(REAL_CASING)

    c = GitHubClient(token="ghp_secret", transport=t, cache=None, use_cache=False)
    with pytest.raises(UntrustedHost):
        c.raw("https://evil.example/collect")
    assert seen == [], "the token was sent off-host"

    c.raw("google/oss-fuzz/master/projects/stb/project.yaml")
    assert seen == ["Bearer ghp_secret"], "the token must still reach GitHub itself"


def test_allowed_hosts_still_work_both_relative_and_absolute():
    c = GitHubClient(token="", transport=transport_returning(), cache=None, use_cache=False)
    assert c.api("/repos/o/r").ok
    assert c.api("https://api.github.com/repos/o/r").ok
    assert c.raw("o/r/HEAD/SECURITY.md").ok
    assert c.raw("https://raw.githubusercontent.com/o/r/HEAD/SECURITY.md").ok


@pytest.mark.parametrize("value", ["file:///etc/passwd", "", "../../etc/passwd",
                                   "//evil.example/x", "ftp://evil.example/x"])
def test_non_http_values_are_confined_to_an_allowed_host(value):
    """These do not start with 'http', so they are treated as a path and get
    prefixed onto the trusted host. That is safe - the guarantee being asserted
    is that no request ever LEAVES for a host outside the allowlist, not that
    every odd string raises."""
    calls = []
    c = GitHubClient(token="ghp_secret", transport=transport_returning(record=calls),
                     cache=None, use_cache=False)
    try:
        c.raw(value)
    except UntrustedHost:
        return  # refusing outright is also fine
    assert len(calls) == 1
    host = urlparse(calls[0]).hostname
    assert host in ("raw.githubusercontent.com", "api.github.com"), host
