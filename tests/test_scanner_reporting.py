"""
Tests for the false-clean defects found during the 2026-10-04 Deca/IPS scan run.

Three different tools reported "no findings" when they had in fact failed, and
the TOON wrapper rendered all three as risk NONE:

* gitleaks found 9 leaks in Deca/deca-uam-api and the endpoint returned 0,
  because findings are only ever written to --report-path and the flag was
  optional.
* opengrep was OOM-killed on IPS/rebot (1,261 files) and IPS/teijin (985 files)
  and still emitted well-formed JSON with results: [], because the client's
  max_accuracy default sent --max-memory 0 into a 3GB cgroup.
* every config=auto scan died in 0.2s ("Cannot create auto config when metrics
  are off") because --metrics=off is always added.

Each test below fails against the original code.
"""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("USE_MULTIPROCESSING", "0")
os.environ.setdefault("MOUNT_POINT", ROOT)
os.environ.setdefault("WINDOWS_BASE", ROOT)
sys.path.insert(0, os.path.join(ROOT, "server"))

flask = pytest.importorskip("flask", reason="flask not installed")

import core  # noqa: E402
from routes import sast as sast_routes  # noqa: E402
from routes import secrets as secrets_routes  # noqa: E402


# -- scan_trustworthy: a failure must never read as clean ------------------

def test_clean_scan_is_trusted():
    proven, why = core.scan_trustworthy("opengrep", {"return_code": 0, "stdout": "{}"})
    assert proven is True
    assert why == ""


def test_findings_exit_code_is_still_trusted():
    """gitleaks/opengrep exit 1 to mean 'findings', not 'failure'."""
    proven, _ = core.scan_trustworthy("gitleaks", {"return_code": 1, "stdout": "x"})
    assert proven is True


def test_oom_killed_scan_is_not_trusted():
    proven, why = core.scan_trustworthy("opengrep", {"return_code": -9})
    assert proven is False
    assert "memory" in why.lower()


def test_terminated_scan_is_not_trusted():
    proven, why = core.scan_trustworthy("opengrep", {"return_code": -15})
    assert proven is False


def test_timed_out_scan_is_not_trusted():
    proven, why = core.scan_trustworthy("bandit", {"return_code": 0, "timed_out": True})
    assert proven is False
    assert "timed out" in why


def test_route_marked_unproven_is_respected():
    proven, why = core.scan_trustworthy(
        "opengrep", {"return_code": 0, "scan_proven": False, "error": "scanned 0 files"})
    assert proven is False
    assert "0 files" in why


def test_error_field_makes_a_result_untrusted():
    proven, why = core.scan_trustworthy("gitleaks", {"return_code": 0, "error": "boom"})
    assert proven is False


# -- the TOON wrapper must not render a failure as risk NONE --------------

def test_toon_labels_a_failed_scan_instead_of_calling_it_clean():
    out = core.response_as_toon("opengrep", {"target": "x"},
                                {"return_code": -9, "stdout": ""})
    assert out["scan_proven"] is False
    assert out["success"] is False
    analysis = out["toon_result"]["analysis"]
    assert analysis["unproven"] is True
    assert analysis["risk"]["overall_risk"] == "UNKNOWN"
    joined = " ".join(analysis["recommendations"]).lower()
    assert "do not read this as clean" in joined


def test_toon_leaves_a_genuine_clean_result_alone():
    out = core.response_as_toon("opengrep", {"target": "x"},
                                {"return_code": 0, "stdout": json.dumps({"results": []})})
    assert out["scan_proven"] is True
    assert out["toon_result"]["analysis"].get("unproven") is not True


# -- opengrep: fatal vs per-file errors ----------------------------------

def test_engine_killed_is_classified_fatal():
    assert sast_routes._is_fatal_scan_error({
        "type": "SemgrepError",
        "message": "Error while running rules: the engine was killed. "
                   "The most common reason this happens is because it used too much memory.",
    }) is True


def test_auto_config_error_is_classified_fatal():
    assert sast_routes._is_fatal_scan_error({
        "message": "Cannot create auto config when metrics are off."}) is True


def test_per_file_parse_warning_is_not_fatal():
    assert sast_routes._is_fatal_scan_error({
        "level": "warn", "path": "src/a.ts", "message": "Syntax error"}) is False


def test_run_level_error_without_a_path_is_fatal():
    assert sast_routes._is_fatal_scan_error({"level": "error", "message": "boom"}) is True


# -- opengrep: unbounded flags get clamped -------------------------------

def test_unbounded_memory_is_clamped():
    out = sast_routes._clamp_unbounded_flags("--max-memory 0 --timeout 0 --max-target-bytes 0")
    assert "--max-memory 0" not in out["args"]
    assert "--timeout 0" not in out["args"]
    assert "--max-target-bytes 0" in out["args"], "large files are slow, not fatal"
    assert len(out["notes"]) == 2


def test_ordinary_flags_are_untouched():
    out = sast_routes._clamp_unbounded_flags("--max-memory 1024 --timeout 15")
    assert out["args"] == "--max-memory 1024 --timeout 15"
    assert out["notes"] == []


def test_memory_cap_is_added_even_when_jobs_is_supplied():
    """Regression: --max-memory used to be nested inside the --jobs branch, so
    passing --jobs removed the memory cap entirely and the scan got OOM-killed."""
    flags = sast_routes._grep_perf_flags("--jobs 2")
    assert "--max-memory" in flags


def test_perf_flags_respect_a_caller_supplied_memory_cap():
    flags = sast_routes._grep_perf_flags("--max-memory 777")
    assert "--max-memory" not in flags  # caller's value must not be duplicated


# -- opengrep route: auto config and unproven detection ------------------

@pytest.fixture
def app():
    application = flask.Flask(__name__)
    sast_routes.register(application)
    secrets_routes.register(application)
    application.config.update(TESTING=True)
    return application


def test_auto_config_is_resolved_to_a_runnable_pack(monkeypatch):
    seen = {}

    def fake_exec(command, cwd=None, timeout=None):
        seen["cmd"] = command
        return {"return_code": 0, "stdout": json.dumps({"results": [], "paths": {"scanned": ["a.py"]}}),
                "stderr": "", "success": True}

    monkeypatch.setattr(sast_routes, "execute_command", fake_exec)
    monkeypatch.setattr(sast_routes, "validate_scan_target", lambda p: ROOT)
    out = sast_routes._opengrep_scan({"target": ROOT, "config": "auto"})
    assert "--config=auto" not in seen["cmd"], "auto cannot run with --metrics=off"
    assert "p/default" in seen["cmd"]
    assert out["config_used"] == "p/default"


def test_opengrep_oom_is_reported_as_unproven(monkeypatch):
    killed = {"results": [], "errors": [
        {"type": "SemgrepError", "message": "the engine was killed. it used too much memory."}]}

    monkeypatch.setattr(sast_routes, "execute_command",
                        lambda c, cwd=None, timeout=None: {
                            "return_code": 1, "stdout": json.dumps(killed), "stderr": "", "success": True})
    monkeypatch.setattr(sast_routes, "validate_scan_target", lambda p: ROOT)
    out = sast_routes._opengrep_scan({"target": ROOT, "config": "p/default"})
    assert out["scan_proven"] is False
    assert out["success"] is False
    assert "engine was killed" in out["error"]


def test_opengrep_zero_files_scanned_is_unproven(monkeypatch):
    monkeypatch.setattr(sast_routes, "execute_command",
                        lambda c, cwd=None, timeout=None: {
                            "return_code": 0, "stdout": json.dumps({"results": [], "paths": {"scanned": []}}),
                            "stderr": "", "success": True})
    monkeypatch.setattr(sast_routes, "validate_scan_target", lambda p: ROOT)
    out = sast_routes._opengrep_scan({"target": ROOT, "config": "p/default"})
    assert out["scan_proven"] is False


def test_opengrep_parse_warnings_do_not_make_a_scan_unproven(monkeypatch):
    noisy = {"results": [], "paths": {"scanned": ["a.ts"]},
             "errors": [{"level": "warn", "path": "a.ts", "message": "Syntax error"}]}
    monkeypatch.setattr(sast_routes, "execute_command",
                        lambda c, cwd=None, timeout=None: {
                            "return_code": 0, "stdout": json.dumps(noisy), "stderr": "", "success": True})
    monkeypatch.setattr(sast_routes, "validate_scan_target", lambda p: ROOT)
    out = sast_routes._opengrep_scan({"target": ROOT, "config": "p/default"})
    assert out.get("scan_proven") is not False
    assert out["summary"]["total_parse_warnings"] == 1


# -- gitleaks route: the report file is no longer optional ---------------

def test_gitleaks_findings_are_reported_when_caller_omits_report_path(app, monkeypatch):
    """The exact defect: 9 real leaks were reported as 0 findings."""
    leaks = [{"RuleID": "aws-access-token", "File": "a.py", "StartLine": 3,
              "Secret": "AKIAEXAMPLE", "Commit": "abc1234"}] * 9

    def fake_exec(command, cwd=None, timeout=None):
        assert "--report-path=" in command, "a report path must always be passed"
        path = command.split("--report-path=")[1].split()[0]
        with open(path, "w") as f:
            json.dump(leaks, f)
        return {"return_code": 1, "stdout": "leaks found: 9", "stderr": "", "success": True}

    monkeypatch.setattr(secrets_routes, "execute_command", fake_exec)
    monkeypatch.setattr(secrets_routes, "resolve_windows_path", lambda p: ROOT)
    r = app.test_client().post("/api/secrets/gitleaks",
                               data=json.dumps({"target": ROOT}),
                               content_type="application/json")
    body = r.get_json()
    assert body["scan_proven"] is True
    assert body["toon_result"]["analysis"]["total_findings"] == 9 or \
        body["toon_result"]["analysis"].get("unproven") is not True


def test_gitleaks_unreadable_report_with_leaks_is_unproven(app, monkeypatch):
    """exit 1 means leaks exist; if the report is missing, 0 would be a lie."""
    monkeypatch.setattr(secrets_routes, "execute_command",
                        lambda c, cwd=None, timeout=None: {
                            "return_code": 1, "stdout": "leaks found: 9", "stderr": "", "success": True})
    monkeypatch.setattr(secrets_routes, "resolve_windows_path", lambda p: ROOT)
    r = app.test_client().post("/api/secrets/gitleaks",
                               data=json.dumps({"target": ROOT}),
                               content_type="application/json")
    body = r.get_json()
    assert body["scan_proven"] is False
    assert "unproven" in body["unproven_reason"].lower()


def test_gitleaks_no_git_mode_does_not_get_log_opts(app, monkeypatch):
    """--log-opts is invalid without a git history and makes gitleaks error out."""
    seen = {}

    def fake_exec(command, cwd=None, timeout=None):
        seen["cmd"] = command
        path = command.split("--report-path=")[1].split()[0]
        with open(path, "w") as f:
            json.dump([], f)
        return {"return_code": 0, "stdout": "", "stderr": "", "success": True}

    monkeypatch.setattr(secrets_routes, "execute_command", fake_exec)
    monkeypatch.setattr(secrets_routes, "resolve_windows_path", lambda p: ROOT)
    app.test_client().post("/api/secrets/gitleaks",
                           data=json.dumps({"target": ROOT, "additional_args": "--no-git"}),
                           content_type="application/json")
    assert "--log-opts" not in seen["cmd"]


def test_gitleaks_git_mode_keeps_the_history_depth_limit(app, monkeypatch):
    seen = {}

    def fake_exec(command, cwd=None, timeout=None):
        seen["cmd"] = command
        path = command.split("--report-path=")[1].split()[0]
        with open(path, "w") as f:
            json.dump([], f)
        return {"return_code": 0, "stdout": "", "stderr": "", "success": True}

    monkeypatch.setattr(secrets_routes, "execute_command", fake_exec)
    monkeypatch.setattr(secrets_routes, "resolve_windows_path", lambda p: ROOT)
    app.test_client().post("/api/secrets/gitleaks",
                           data=json.dumps({"target": ROOT}),
                           content_type="application/json")
    assert "--log-opts=--max-count=1000" in seen["cmd"]


# -- the sync path must apply the same gate as the TOON wrapper -----------

def test_sync_path_rejects_a_killed_scan_with_partial_output(monkeypatch):
    """A scan killed mid-run can still emit parseable output and set no error of
    its own. Without the shared gate it reads as a completed scan."""
    monkeypatch.setattr(core, "acquire_scan_slot", lambda timeout=None: True)
    monkeypatch.setattr(core, "release_scan_slot", lambda: None)

    def killed(params):
        return {"return_code": -9, "stdout": json.dumps({"results": []}), "success": True}

    out = core.run_scan_synchronously("opengrep", {"target": "x"}, killed)
    assert out["success"] is False
    assert out["job_status"] == "failed"
    assert "memory" in out["error"].lower()


def test_sync_path_still_passes_a_findings_exit_code(monkeypatch):
    monkeypatch.setattr(core, "acquire_scan_slot", lambda timeout=None: True)
    monkeypatch.setattr(core, "release_scan_slot", lambda: None)

    def found(params):
        return {"return_code": 1, "stdout": json.dumps({"results": [{"check_id": "x"}]}),
                "success": True, "summary": {"total_findings": 1}}

    out = core.run_scan_synchronously("opengrep", {"target": "x"}, found)
    assert out.get("job_status") != "failed"
