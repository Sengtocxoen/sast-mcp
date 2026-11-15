"""
Tests for scan gaps seen in a fleet-wide repo-scan run.

* A large Go monorepo had no gosec result: one `gosec ./...` over every module was
  OOM-killed. gosec now runs per module and splits a module that fails.
* A Terraform repo had no tfsec result: tfsec 1.x stops on an `import` block, and the
  stored error was the first 300 chars of stderr, i.e. tfsec's banner.
* A large repo was scanned from a partial copy (tar timed out) with no
  error, and the timed-out tar kept running because only the shell was killed.
* graudit reported exactly 2000 matches: the stored list's cut-off, not a count.
"""
import json
import os
import shlex
import subprocess
import sys
import time
from collections import Counter

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("USE_MULTIPROCESSING", "0")
os.environ.setdefault("MOUNT_POINT", ROOT)
os.environ.setdefault("WINDOWS_BASE", ROOT)
sys.path.insert(0, os.path.join(ROOT, "server"))

pytest.importorskip("flask", reason="flask not installed")

import core  # noqa: E402
import staging  # noqa: E402
from routes import repo_scan  # noqa: E402


def _ctx(langs):
    return {"langs": Counter(langs), "markers": {}, "req_files": [],
            "tf_dirs": [], "npm_dirs": []}


@pytest.fixture
def tools(monkeypatch):
    monkeypatch.setattr(repo_scan.tool_registry, "have", lambda t: True)
    monkeypatch.setattr(repo_scan.tool_registry, "binary_for", lambda t: t)
    monkeypatch.setattr(repo_scan, "resolve_grep_engine", lambda: "semgrep")
    monkeypatch.setattr(repo_scan, "_grep_jobs_mem", lambda: (4, 2000))


# -- gosec ------------------------------------------------------------------

def _write(path, text="package x\n"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)


@pytest.fixture
def monorepo(tmp_path):
    """Two modules. apps/api fails as a whole; its folders scan on their own."""
    r = tmp_path / "repo"
    _write(str(r / "apps/api/go.mod"), "module api\n")
    _write(str(r / "apps/api/main.go"))
    _write(str(r / "apps/api/internal/a/a.go"))
    _write(str(r / "apps/api/internal/b/b.go"))
    _write(str(r / "apps/api/scripts/s.go"))
    _write(str(r / "apps/api/docs/README.md"), "no go here\n")
    _write(str(r / "pkg/go.mod"), "module pkg\n")
    _write(str(r / "pkg/p.go"))
    _write(str(r / "node_modules/x/go.mod"), "module skipped\n")
    out = tmp_path / "out"
    out.mkdir()
    return str(r), str(out / "gosec.json")


def _fake_gosec(fail):
    """execute_command stand-in: writes one issue per run unless the run is in `fail`."""
    calls = []

    def run(cmd, timeout=None):
        tok = shlex.split(cmd)
        mod_dir, tmp, pattern = tok[1], next(t[5:] for t in tok if t.startswith("-out=")), tok[-1]
        label = os.path.basename(mod_dir.rstrip("/\\")) + ":" + pattern
        calls.append(label)
        assert "GOFLAGS=-p=1" in tok and any(t.startswith("GOMEMLIMIT=") for t in tok)
        if label in fail:
            return {"return_code": 143, "stderr": "Terminated", "timed_out": False}
        with open(tmp, "w") as fh:
            json.dump({"Issues": [{"rule_id": "G104", "file": label}]}, fh)
        return {"return_code": 0, "stderr": "", "timed_out": False}
    return run, calls


def test_go_modules_are_found_and_vendor_dirs_skipped(monorepo):
    dest, _ = monorepo
    assert repo_scan._go_modules(dest) == ["apps/api", "pkg"]


def test_a_repo_without_go_mod_is_one_module(tmp_path):
    assert repo_scan._go_modules(str(tmp_path)) == ["."]


def test_subdirs_skip_folders_without_go_code(monorepo):
    dest, _ = monorepo
    assert repo_scan._go_subdirs(os.path.join(dest, "apps", "api")) == ["internal", "scripts"]


def test_gosec_runs_each_module_on_its_own(monorepo, monkeypatch):
    dest, report = monorepo
    run, calls = _fake_gosec(fail=set())
    monkeypatch.setattr(repo_scan, "execute_command", run)
    res = repo_scan._run_gosec(dest, report, 600)
    assert calls == ["api:./...", "pkg:./..."]
    assert res["findings"] == 2 and "incomplete" not in res
    assert len(json.load(open(report))["Issues"]) == 2


def test_a_module_that_fails_is_split_into_its_folders(monorepo, monkeypatch):
    dest, report = monorepo
    run, calls = _fake_gosec(fail={"api:./..."})
    monkeypatch.setattr(repo_scan, "execute_command", run)
    res = repo_scan._run_gosec(dest, report, 600)
    # root package, then each folder with Go code; docs/ has none
    assert calls == ["api:./...", "api:.", "api:./internal/...", "api:./scripts/...", "pkg:./..."]
    assert res["findings"] == 4
    assert "incomplete" not in res, "the parts replaced the failed whole"


def test_a_part_that_still_fails_is_listed_not_dropped(monorepo, monkeypatch):
    dest, report = monorepo
    fail = {"api:./...", "api:./internal/...", "api:./internal/a/..."}
    run, calls = _fake_gosec(fail=fail)
    monkeypatch.setattr(repo_scan, "execute_command", run)
    res = repo_scan._run_gosec(dest, report, 600)
    assert "api:./internal/b/..." in calls
    assert list(res["incomplete"]) == ["apps/api:./internal/a/..."]
    assert "rc=143" in res["incomplete"]["apps/api:./internal/a/..."]
    assert json.load(open(report))["Modules"]["failed"] == res["incomplete"]


def test_no_report_is_written_when_every_run_fails(monorepo, monkeypatch):
    """An empty report would read as a clean scan."""
    dest, report = monorepo
    monkeypatch.setattr(repo_scan, "execute_command",
                        lambda cmd, timeout=None: {"return_code": 143, "stderr": "Terminated"})
    res = repo_scan._run_gosec(dest, report, 600)
    assert not os.path.exists(report)
    assert res["error"] and res["incomplete"]


def test_gosec_stops_when_its_time_is_used_up(monorepo, monkeypatch):
    dest, report = monorepo
    run, calls = _fake_gosec(fail=set())
    monkeypatch.setattr(repo_scan, "execute_command", run)
    res = repo_scan._run_gosec(dest, report, 10)  # under the 30 s floor
    assert calls == [] and res["timed_out"] is True


def test_plan_uses_the_per_module_runner(tools, tmp_path):
    plan = repo_scan._build_plan(_ctx({".go": 9}), str(tmp_path), str(tmp_path), {})
    entry = next(p for p in plan if p["tool"] == "gosec")
    assert callable(entry.get("runner"))
    assert "./..." not in entry["command"], "no whole-repo gosec run"


def test_runner_entries_bypass_the_shell(monkeypatch):
    monkeypatch.setattr(repo_scan, "_run_tool", lambda *a: pytest.fail("shell path used"))
    out = repo_scan._run_plan_parallel([{"tool": "gosec", "command": "x", "report": "r",
                                         "timeout": 1, "runner": lambda: {"tool": "gosec"}}])
    assert out == [{"tool": "gosec"}]


# -- tfsec ------------------------------------------------------------------

def test_tfsec_ignores_hcl_it_cannot_parse(tools, tmp_path):
    plan = repo_scan._build_plan(_ctx({".tf": 3}), str(tmp_path), str(tmp_path), {})
    cmd = next(p["command"] for p in plan if p["tool"] == "tfsec")
    assert "--ignore-hcl-errors" in cmd


TFSEC_STDERR = """
======================================================
tfsec is joining the Trivy family

tfsec will continue to remain available
for the time being, although our engineering
attention will be directed at Trivy going forward.

You can read more here:
https://github.com/aquasecurity/tfsec/discussions/1994
======================================================
Error: scan failed: projects/x/users.tf:5,1-7: Unsupported block type; Blocks of type "import" are not expected here.
"""


def test_error_text_keeps_the_error_not_the_banner():
    msg = repo_scan._error_text({"stderr": TFSEC_STDERR})
    assert msg.startswith("Error: scan failed") and "import" in msg


def test_error_text_falls_back_to_the_tail():
    assert repo_scan._error_text({"stderr": "a" * 500 + "END"}).endswith("END")
    assert repo_scan._error_text({}) == "no output"


# -- graudit ----------------------------------------------------------------

def test_graudit_count_is_not_capped_at_2000(tmp_path):
    p = tmp_path / "graudit.json"
    p.write_text("".join(f"src/a.py:{i}:eval(x)\n" for i in range(1, 2501)))
    repo_scan._graudit_to_json(str(p))
    data = json.load(open(p))
    assert len(data["matches"]) == 2000
    res = repo_scan._parse_findings(str(p), "graudit")
    assert res == {"findings": 2500, "truncated": True}


def test_graudit_old_reports_still_parse(tmp_path):
    p = tmp_path / "graudit.json"
    p.write_text(json.dumps({"matches": [{"file": "a", "line": 1}]}))
    assert repo_scan._parse_findings(str(p), "graudit") == {"findings": 1}


# -- staging ----------------------------------------------------------------

@pytest.fixture
def slow_repo(tmp_path, monkeypatch):
    monkeypatch.setattr(repo_scan, "_fstype", lambda p: "fuse.vmhgfs-fuse")
    src = tmp_path / "repo"
    src.mkdir()
    for n in ("a.py", "b.py", "c.py"):
        (src / n).write_text("x = 1\n")
    base = tmp_path / "stage"
    base.mkdir()
    return str(src), str(base)


def _tar(files, **res):
    def run(cmd, timeout=None):
        dest = shlex.split(cmd.split("|")[1])[2]
        for n in files:
            with open(os.path.join(dest, n), "w") as fh:
                fh.write("x\n")
        return {"return_code": 0, "stderr": "", **res}
    return run


def test_a_timed_out_copy_is_flagged(slow_repo, monkeypatch):
    src, base = slow_repo
    monkeypatch.setattr(repo_scan, "execute_command",
                        _tar(["a.py"], timed_out=True, return_code=-1))
    out = repo_scan._stage_local(src, base)
    assert out["stage_defect"] == "tar timed out"


def test_a_short_copy_is_flagged(slow_repo, monkeypatch):
    src, base = slow_repo
    monkeypatch.setattr(repo_scan, "execute_command", _tar(["a.py"]))
    out = repo_scan._stage_local(src, base)
    assert "1 of 3" in out["stage_defect"]


def test_a_complete_copy_has_no_defect(slow_repo, monkeypatch):
    src, base = slow_repo
    monkeypatch.setattr(repo_scan, "execute_command", _tar(["a.py", "b.py", "c.py"]))
    assert "stage_defect" not in repo_scan._stage_local(src, base)


def test_staging_uses_the_shared_timeout(slow_repo, monkeypatch):
    src, base = slow_repo
    seen = {}

    def run(cmd, timeout=None):
        seen["timeout"] = timeout
        return _tar(["a.py", "b.py", "c.py"])(cmd)
    monkeypatch.setattr(repo_scan, "execute_command", run)
    repo_scan._stage_local(src, base)
    assert seen["timeout"] == staging.STAGE_TIMEOUT


def test_timeout_is_named_even_when_tar_exits_minus_one():
    """A killed tar exits -1; the reason must still say it timed out."""
    res = {"return_code": -1, "timed_out": True, "stderr": ""}
    assert staging._copy_defect("/x", "/y", res, frozenset()) == "tar timed out"


# -- timeouts kill the whole process group ----------------------------------

@pytest.mark.skipif(not hasattr(os, "killpg"), reason="POSIX process groups only")
def test_timeout_kills_child_processes(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "wrap_with_memory_limit", lambda c: c)
    pidfile = tmp_path / "child.pid"
    res = core.execute_command(f"sleep 60 & echo $! > {pidfile}; wait", timeout=1)
    assert res["timed_out"] is True
    child = int(pidfile.read_text())
    for _ in range(20):  # give the kernel a moment to reap it
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            return
        if subprocess.run(["ps", "-o", "stat=", "-p", str(child)],
                          capture_output=True, text=True).stdout.strip().startswith("Z"):
            return
        time.sleep(0.1)
    os.kill(child, 9)
    pytest.fail("the child outlived the timeout (orphan process)")
