"""Tests for making OWASP Dependency-Check actually runnable.

The tool was installed on the Kali box, reported working by `--version`, and
could not run a single scan. Three separate reasons, each covered here:

* /health said "dependency-check": false and the scan route produced
  `/bin/sh: 1: dependency-check: not found`, because the binary name was
  hard-coded to `dependency-check` while the release tarball installs
  `dependency-check.sh`.
* the NVD cache defaults to `[JAR]/data` inside root-owned
  /opt/dependency-check, which the server user cannot create, so every scan
  would die building the H2 database.
* the NVD API key was accepted only as a request parameter and appended to the
  command as `--nvdApiKey <key>`, which puts a credential in argv (world
  readable via /proc) and in the command string this server copies into every
  scan result and log line.
"""
import os
import shlex
import stat
import sys
from collections import Counter

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("USE_MULTIPROCESSING", "0")
os.environ.setdefault("MOUNT_POINT", ROOT)
os.environ.setdefault("WINDOWS_BASE", ROOT)
sys.path.insert(0, os.path.join(ROOT, "server"))

flask = pytest.importorskip("flask", reason="flask not installed")

import config  # noqa: E402
import core  # noqa: E402
from routes import dependencies as deps_routes  # noqa: E402
from routes import repo_scan  # noqa: E402


# -- the key must never travel in a command string ------------------------

def test_redact_command_masks_an_nvd_key_argument():
    out = core.redact_command("dependency-check.sh --scan /x --nvdApiKey s3cr3t-key -f JSON")
    assert "s3cr3t-key" not in out
    assert "REDACTED" in out
    assert "--scan /x" in out


def test_redact_command_masks_a_property_assignment():
    assert "s3cr3t" not in core.redact_command("java -Dnvd.api.key=s3cr3t -jar x.jar")


def test_redact_command_masks_tokens_and_passwords():
    for arg in ("--token abc123", "--api-key abc123", "--password abc123",
                "--apikey=abc123", "--auth-token abc123"):
        assert "abc123" not in core.redact_command("tool " + arg), arg


def test_redact_command_leaves_ordinary_arguments_alone():
    cmd = "semgrep scan --config=p/python --json --max-memory 2000 /src"
    assert core.redact_command(cmd) == cmd


@pytest.mark.skipif(os.name != "posix", reason="CommandExecutor uses os.setsid")
def test_executor_result_does_not_echo_a_key():
    """The command field travels to API clients, job records and logs."""
    result = core.execute_command("echo --nvdApiKey s3cr3t-key", timeout=30)
    assert "s3cr3t-key" not in result.get("command", "")


# -- the property file ------------------------------------------------------

def test_property_file_holds_the_key_and_is_private():
    path = deps_routes._write_nvd_property_file("s3cr3t-key")
    try:
        with open(path) as handle:
            assert handle.read().strip() == "nvd.api.key=s3cr3t-key"
        if os.name == "posix":
            mode = stat.S_IMODE(os.stat(path).st_mode)
            assert mode == 0o600, oct(mode)
    finally:
        os.remove(path)


def test_nvd_cache_present_detects_an_empty_dir(tmp_path):
    assert deps_routes._nvd_cache_present(str(tmp_path)) is False
    (tmp_path / "odc.mv.db").write_text("x")
    assert deps_routes._nvd_cache_present(str(tmp_path)) is True


def test_nvd_cache_present_on_a_missing_dir_is_false(tmp_path):
    assert deps_routes._nvd_cache_present(str(tmp_path / "nope")) is False


# -- the route --------------------------------------------------------------

@pytest.fixture
def client(monkeypatch):
    app = flask.Flask(__name__)
    deps_routes.register(app)
    return app.test_client()


def _post(client, **body):
    return client.post("/api/dependencies/dependency-check", json=body)


def test_route_refuses_rather_than_crawl_for_hours(client, monkeypatch, tmp_path):
    """Empty cache and no key is reported, not attempted.

    Unauthenticated callers get 5 NVD requests per 30 seconds. Starting that
    run would block the caller until a timeout, which is indistinguishable
    from a clean scan.
    """
    monkeypatch.setattr(deps_routes, "NVD_API_KEY", "")
    called = []
    monkeypatch.setattr(deps_routes, "execute_command",
                        lambda *a, **k: called.append(a) or {})
    resp = _post(client, target=ROOT, data_dir=str(tmp_path / "empty"))
    assert resp.status_code == 503
    body = resp.get_json()
    assert "warm-nvd-cache" in body["hint"]
    assert called == [], "the scan must not start"


def test_route_runs_with_a_key_and_keeps_it_out_of_argv(client, monkeypatch, tmp_path):
    monkeypatch.setattr(deps_routes, "NVD_API_KEY", "s3cr3t-key")
    seen = {}
    written = {}

    real_writer = deps_routes._write_nvd_property_file

    def recording_writer(api_key):
        path = real_writer(api_key)
        written["path"] = path
        with open(path) as handle:
            written["contents"] = handle.read()
        return path

    monkeypatch.setattr(deps_routes, "_write_nvd_property_file", recording_writer)
    monkeypatch.setattr(deps_routes, "execute_command",
                        lambda command, **k: seen.update(command=command) or
                        {"success": True, "stdout": "", "stderr": "", "return_code": 0})
    resp = _post(client, target=ROOT, data_dir=str(tmp_path / "cache"))
    assert resp.status_code == 200

    # The key reaches the tool through the property file...
    assert "nvd.api.key=s3cr3t-key" in written["contents"]
    assert shlex.quote(written["path"]) in seen["command"]
    # ...and never through the command line.
    assert "s3cr3t-key" not in seen["command"]
    assert "--nvdApiKey" not in seen["command"]
    # ...and the file is gone once the scan finishes.
    assert not os.path.exists(written["path"])


def test_route_passes_a_writable_data_dir(client, monkeypatch, tmp_path):
    """Without --data the tool writes beside its jar, in a root-owned dir."""
    monkeypatch.setattr(deps_routes, "NVD_API_KEY", "s3cr3t-key")
    seen = {}
    monkeypatch.setattr(deps_routes, "execute_command",
                        lambda command, **k: seen.update(command=command) or
                        {"success": True, "stdout": "", "stderr": "", "return_code": 0})
    cache = tmp_path / "cache"
    resp = _post(client, target=ROOT, data_dir=str(cache))
    assert resp.status_code == 200
    assert f"--data {cache}" in seen["command"] or f"--data '{cache}'" in seen["command"]
    assert cache.is_dir(), "the route creates the cache dir"


def test_route_scans_a_warmed_cache_without_a_key(client, monkeypatch, tmp_path):
    """noupdate against an existing cache needs no key and no network."""
    monkeypatch.setattr(deps_routes, "NVD_API_KEY", "")
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "odc.mv.db").write_text("warmed")
    seen = {}
    monkeypatch.setattr(deps_routes, "execute_command",
                        lambda command, **k: seen.update(command=command) or
                        {"success": True, "stdout": "", "stderr": "", "return_code": 0})
    resp = _post(client, target=ROOT, data_dir=str(cache), noupdate=True)
    assert resp.status_code == 200
    assert " -n" in seen["command"]
    assert "-P " not in seen["command"]


def test_route_refuses_noupdate_against_an_empty_cache(client, monkeypatch, tmp_path):
    """Nothing to match against is not a clean scan."""
    monkeypatch.setattr(deps_routes, "NVD_API_KEY", "s3cr3t-key")
    called = []
    monkeypatch.setattr(deps_routes, "execute_command",
                        lambda *a, **k: called.append(a) or {})
    resp = _post(client, target=ROOT, data_dir=str(tmp_path / "empty"), noupdate=True)
    assert resp.status_code == 503
    assert "warm-nvd-cache" in resp.get_json()["hint"]
    assert called == []


def test_project_name_from_a_request_cannot_inject_a_command(client, monkeypatch, tmp_path):
    monkeypatch.setattr(deps_routes, "NVD_API_KEY", "s3cr3t-key")
    seen = {}
    monkeypatch.setattr(deps_routes, "execute_command",
                        lambda command, **k: seen.update(command=command) or
                        {"success": True, "stdout": "", "stderr": "", "return_code": 0})
    payload = "x; touch /tmp/pwned"
    resp = _post(client, target=ROOT, data_dir=str(tmp_path / "c"),
                 project_name=payload)
    assert resp.status_code == 200
    # Quoted as a single argument, so the shell cannot see the semicolon.
    assert shlex.quote(payload) in seen["command"]


# -- the binary name --------------------------------------------------------

def test_resolver_prefers_the_name_the_installer_produces(monkeypatch):
    monkeypatch.delenv("DEPENDENCY_CHECK_PATH", raising=False)
    monkeypatch.setattr(config.shutil, "which",
                        lambda n: "/usr/local/bin/dependency-check.sh"
                        if n == "dependency-check.sh" else None)
    assert config._resolve_dependency_check() == "dependency-check.sh"


def test_resolver_accepts_a_distro_packaged_name(monkeypatch):
    monkeypatch.delenv("DEPENDENCY_CHECK_PATH", raising=False)
    monkeypatch.setattr(config.shutil, "which",
                        lambda n: "/usr/bin/dependency-check"
                        if n == "dependency-check" else None)
    assert config._resolve_dependency_check() == "dependency-check"


def test_resolver_honours_an_explicit_path(monkeypatch):
    monkeypatch.setenv("DEPENDENCY_CHECK_PATH", "/opt/dc/bin/dependency-check.sh")
    assert config._resolve_dependency_check() == "/opt/dc/bin/dependency-check.sh"


# -- the fleet scan ---------------------------------------------------------

@pytest.fixture
def plan_env(monkeypatch):
    monkeypatch.setattr(repo_scan.tool_registry, "have", lambda t: True)
    monkeypatch.setattr(repo_scan.tool_registry, "binary_for", lambda t: t)
    monkeypatch.setattr(repo_scan, "resolve_grep_engine", lambda: "semgrep")
    monkeypatch.setattr(repo_scan, "_grep_jobs_mem", lambda: (4, 2000))
    monkeypatch.setitem(repo_scan._eslint_probe, "major", 9)
    monkeypatch.setitem(repo_scan._eslint_probe, "plugin_dir", "/usr/lib/node_modules")


def _ctx(langs, markers):
    return {"langs": Counter(langs), "markers": markers, "req_files": [],
            "tf_dirs": [], "npm_dirs": []}


def _dc_cmd(plan):
    for entry in plan:
        if entry["tool"] == "dependency-check":
            return entry["command"]
    return ""


def test_fleet_scan_points_dependency_check_at_a_writable_cache(plan_env, tmp_path):
    """--noupdate with no --data reads a cache the server cannot create."""
    plan = repo_scan._build_plan(
        _ctx({".java": 20}, {"pom.xml"}), str(tmp_path), str(tmp_path), {})
    cmd = _dc_cmd(plan)
    assert cmd, "a Maven repo should get dependency-check"
    assert "--data" in cmd
    assert "--noupdate" in cmd


def test_fleet_scan_skips_npm_repos_by_default(plan_env, tmp_path):
    plan = repo_scan._build_plan(
        _ctx({".js": 20}, {"package-lock.json"}), str(tmp_path), str(tmp_path), {})
    assert _dc_cmd(plan) == ""


def test_fleet_scan_can_opt_into_other_ecosystems(plan_env, tmp_path, monkeypatch):
    monkeypatch.setattr(repo_scan, "DEPENDENCY_CHECK_ALL_ECOSYSTEMS", True)
    plan = repo_scan._build_plan(
        _ctx({".js": 20}, {"package-lock.json"}), str(tmp_path), str(tmp_path), {})
    assert "--data" in _dc_cmd(plan)


# -- NVD 503 and CISA 403 survival knobs ------------------------------------

def test_update_run_can_widen_the_nvd_delay(client, monkeypatch, tmp_path):
    """Retries have no backoff upstream, so the call delay is the only knob."""
    monkeypatch.setattr(deps_routes, "NVD_API_KEY", "s3cr3t-key")
    monkeypatch.setattr(deps_routes, "NVD_API_DELAY_MS", "6000")
    monkeypatch.setattr(deps_routes, "NVD_MAX_RETRY_COUNT", "30")
    seen = {}
    monkeypatch.setattr(deps_routes, "execute_command",
                        lambda command, **k: seen.update(command=command) or
                        {"success": True, "stdout": "", "stderr": "", "return_code": 0})
    assert _post(client, target=ROOT, data_dir=str(tmp_path / "c")).status_code == 200
    assert "--nvdApiDelay 6000" in seen["command"]
    assert "--nvdMaxRetryCount 30" in seen["command"]


def test_kev_can_be_disabled_when_cisa_blocks_us(client, monkeypatch, tmp_path):
    monkeypatch.setattr(deps_routes, "NVD_API_KEY", "s3cr3t-key")
    monkeypatch.setattr(deps_routes, "DEPENDENCY_CHECK_DISABLE_KEV", True)
    monkeypatch.setattr(deps_routes, "DEPENDENCY_CHECK_KEV_URL", "")
    seen = {}
    monkeypatch.setattr(deps_routes, "execute_command",
                        lambda command, **k: seen.update(command=command) or
                        {"success": True, "stdout": "", "stderr": "", "return_code": 0})
    assert _post(client, target=ROOT, data_dir=str(tmp_path / "c")).status_code == 200
    assert "--disableKnownExploited" in seen["command"]


def test_a_kev_mirror_wins_over_disabling_it(client, monkeypatch, tmp_path):
    monkeypatch.setattr(deps_routes, "NVD_API_KEY", "s3cr3t-key")
    monkeypatch.setattr(deps_routes, "DEPENDENCY_CHECK_DISABLE_KEV", True)
    monkeypatch.setattr(deps_routes, "DEPENDENCY_CHECK_KEV_URL",
                        "https://mirror.internal/kev.json")
    seen = {}
    monkeypatch.setattr(deps_routes, "execute_command",
                        lambda command, **k: seen.update(command=command) or
                        {"success": True, "stdout": "", "stderr": "", "return_code": 0})
    assert _post(client, target=ROOT, data_dir=str(tmp_path / "c")).status_code == 200
    assert "--kevURL https://mirror.internal/kev.json" in seen["command"]
    assert "--disableKnownExploited" not in seen["command"]


def test_update_flags_are_absent_when_not_updating(client, monkeypatch, tmp_path):
    """With -n there is no update, so none of these apply."""
    monkeypatch.setattr(deps_routes, "NVD_API_KEY", "")
    monkeypatch.setattr(deps_routes, "NVD_API_DELAY_MS", "6000")
    monkeypatch.setattr(deps_routes, "DEPENDENCY_CHECK_DISABLE_KEV", True)
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "odc.mv.db").write_text("warmed")
    seen = {}
    monkeypatch.setattr(deps_routes, "execute_command",
                        lambda command, **k: seen.update(command=command) or
                        {"success": True, "stdout": "", "stderr": "", "return_code": 0})
    assert _post(client, target=ROOT, data_dir=str(cache),
                 noupdate=True).status_code == 200
    assert "--nvdApiDelay" not in seen["command"]
    assert "--disableKnownExploited" not in seen["command"]
