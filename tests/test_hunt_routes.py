"""
Route-layer tests: the guards that only exist in the HTTP boundary.

The engine suites cover the analysis; these cover what the request body is
allowed to reach. Both cases here were real defects found by review after the
endpoints were already working:

* a caller-supplied catalog URL was passed straight to the HTTP client, which
  attached GITHUB_TOKEN by token presence rather than by destination - so one
  POST exfiltrated the token to any host, and could reach link-local metadata
  or a localhost admin port on the way;
* the `background: true` path copied the raw request body into the job, so the
  job read local_root without the mount-root confinement the synchronous path
  applies.
"""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# core.py builds a multiprocessing.Manager() at import time, which cannot be
# done under pytest on Windows; the server supports running without it.
os.environ.setdefault("USE_MULTIPROCESSING", "0")
os.environ.setdefault("MOUNT_POINT", os.path.join(ROOT, "docs"))
os.environ.setdefault("WINDOWS_BASE", os.path.join(ROOT, "docs"))

sys.path.insert(0, os.path.join(ROOT, "server"))

flask = pytest.importorskip("flask", reason="flask not installed")


@pytest.fixture(scope="module")
def app():
    from routes import hunt as hunt_routes
    application = flask.Flask(__name__)
    hunt_routes.register(application)
    application.config.update(TESTING=True)
    return application


@pytest.fixture
def api(app):
    return app.test_client()


def post(api, path, payload):
    r = api.post(path, data=json.dumps(payload), content_type="application/json")
    return r.status_code, r.get_json()


# -- SSRF / token leakage -------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://evil.example/README.md",
    "http://169.254.169.254/latest/meta-data/",
    "https://raw.githubusercontent.com.evil.example/x",
    "https://api.github.com@evil.example/x",
    "http://127.0.0.1:6077/api/hunt",
])
def test_catalog_refuses_an_off_github_url(api, url):
    """Either form of the parameter must be rejected, with a 4xx not a 500."""
    st, body = post(api, "/api/hunt/catalog", {"catalog": url})
    assert st == 400, f"{url} returned {st}"
    assert "raw.githubusercontent.com" in body["error"]

    st, body = post(api, "/api/hunt/catalog", {"catalog": "readme", "url": url})
    assert st == 400, f"{url} via url= returned {st}"


def test_catalog_accepts_the_committed_offline_catalogs(api):
    st, body = post(api, "/api/hunt/catalog", {"catalog": "parsers"})
    assert st == 200
    assert body["after_tag_filter"] == 62


def test_catalog_rejects_an_unknown_source(api):
    st, body = post(api, "/api/hunt/catalog", {"catalog": "ftp://x/y"})
    assert st == 400


# -- path confinement ----------------------------------------------------

def test_shape_scan_refuses_a_path_outside_the_mount_roots(api):
    st, body = post(api, "/api/hunt/shape-scan", {"target": "C:/Windows/System32"})
    assert st == 400
    assert "outside" in body["error"] or "allowed" in body["error"]


def test_shape_scan_requires_a_target(api):
    st, body = post(api, "/api/hunt/shape-scan", {})
    assert st == 400


def test_background_gate_rejects_a_local_root_outside_the_mount_roots(api):
    """Confinement applies to the background path as well as the synchronous one."""
    st, body = post(api, "/api/hunt/target-gate", {
        "repos": ["o/r"], "background": True, "local_root": "C:/Windows/System32"})
    assert st == 400
    assert "outside" in body["error"] or "allowed" in body["error"]


def test_background_gate_hands_the_job_the_normalised_path(api, monkeypatch):
    """The job must receive the VALIDATED path, not the raw request value.

    An outside-the-root path is already refused while building the options, so
    this is the case that actually distinguishes the two code paths: a path that
    passes validation but is spelled unnormalised. If the job reads the request
    body directly, the '..' segment survives into the filesystem walk.
    """
    from routes import hunt as hunt_routes

    captured = {}

    def fake_runner(tool_name, params, fn):
        captured["result"] = fn(params)
        return {"job_id": "test", "success": True}

    monkeypatch.setattr(hunt_routes, "run_scan_in_thread", fake_runner)
    monkeypatch.setattr(hunt_routes.hunt_gating, "gate_repos",
                        lambda client, repos, **kw: captured.update(kw) or {"ok": True})

    inside = os.path.join(ROOT, "docs", "hunt-pipeline", "..", "hunt-pipeline")
    st, _ = post(api, "/api/hunt/target-gate", {
        "repos": ["o/r"], "background": True, "local_root": inside})

    assert st == 200
    got = captured.get("local_root")
    assert got, "the job never received a local_root"
    assert ".." not in got, f"the job got the raw, unnormalised body value: {got!r}"


def test_repo_slug_validation_rejects_traversal_and_urls(api):
    for bad in ("../../etc/passwd", "o/r?x=1", "https://evil.example/o/r",
                "o/r/../../x", "", "notaslug"):
        st, body = post(api, "/api/hunt/disclosure", {"repo": bad})
        assert st == 400, f"{bad!r} returned {st}"


# -- discovery endpoints -------------------------------------------------

def test_index_describes_both_stages_with_their_precision(api):
    r = api.get("/api/hunt")
    assert r.status_code == 200
    body = r.get_json()
    assert "100%" in body["headline"]
    assert set(body["stages"]) >= {"A_target_gating", "B_shape_scanning"}


def test_budget_endpoint_reports_the_ceiling(api):
    r = api.get("/api/hunt/budget?repos=62")
    assert r.status_code == 200
    body = r.get_json()
    assert body["cost_estimate"]["metered_requests_total"] == 62 * 3
    assert body["cost_estimate"]["repos_per_hour_unauthenticated"] > 0


def test_evidence_requires_something_to_assess(api):
    st, body = post(api, "/api/hunt/evidence", {})
    assert st == 400


def test_evidence_assesses_an_inline_log(api):
    st, body = post(api, "/api/hunt/evidence",
                    {"log": "nohup: ignoring input\n", "claimed_crashes": 0})
    assert st == 200
    assert body["verdict"] == "unproven"
    assert body["clean_claim_admissible"] is False
