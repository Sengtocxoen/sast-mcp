"""Tests for the changes that make a large repository scannable.

All four come from the 2026-11-16 estate sweep, the first one in which semgrep
actually ran:

* sf-ipark-tools took 2,713s against 112s the week before, a factor of 24 where
  comparable repositories moved 4-6x, because it keeps Next.js bundles in .next
  and every pattern engine read them.
* graudit was killed by its 300s limit on rebot after writing 279 findings, and
  on tsumura-research-paper-search-adm with none. The report file a killed run
  leaves behind is indistinguishable from a finished one.
"""
import os
import sys
from collections import Counter

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("USE_MULTIPROCESSING", "0")
os.environ.setdefault("MOUNT_POINT", ROOT)
os.environ.setdefault("WINDOWS_BASE", ROOT)
sys.path.insert(0, os.path.join(ROOT, "server"))

pytest.importorskip("flask", reason="flask not installed")

from routes import repo_scan  # noqa: E402


# -- generated build output is not source ---------------------------------

@pytest.mark.parametrize("name", [
    ".next", ".nuxt", ".svelte-kit", ".angular", ".turbo", ".parcel-cache",
    ".terraform", ".serverless", ".gradle", "coverage", "target",
])
def test_build_output_is_skipped(name):
    assert name in repo_scan._SKIP_DIRS


@pytest.mark.parametrize("name", ["out", ".cache", "public", "static", "src"])
def test_ambiguous_names_are_not_skipped(name):
    """These have projects that keep real source there, so they stay in scope.

    Locked by a test because the cheap way to speed up a sweep is to add names
    here, and losing source is worse than a slow scan.
    """
    assert name not in repo_scan._SKIP_DIRS


def test_source_directories_are_still_skipped():
    """The original set must survive the split into source/build."""
    for name in ("node_modules", "vendor", ".git", "dist", "build", ".venv"):
        assert name in repo_scan._SKIP_DIRS


def test_staging_copy_never_brings_build_output_to_the_scan_host():
    """_stage_repo passes _SKIP_DIRS to ignore_patterns, so an excluded tree is
    not copied at all - which is what makes this fix help every engine, not just
    the ones that take an --exclude flag."""
    import shutil
    ignore = shutil.ignore_patterns(*repo_scan._SKIP_DIRS)
    ignored = ignore("/repo", [".next", "src", "coverage", "app.js", "node_modules"])
    assert ".next" in ignored and "coverage" in ignored and "node_modules" in ignored
    assert "src" not in ignored and "app.js" not in ignored


# -- the semgrep command ---------------------------------------------------

@pytest.fixture
def plan_env(monkeypatch):
    monkeypatch.setattr(repo_scan.tool_registry, "have", lambda t: True)
    monkeypatch.setattr(repo_scan.tool_registry, "binary_for", lambda t: t)
    monkeypatch.setattr(repo_scan, "resolve_grep_engine", lambda: "semgrep")
    monkeypatch.setattr(repo_scan, "_grep_jobs_mem", lambda: (4, 2000))
    monkeypatch.setitem(repo_scan._eslint_probe, "major", 9)
    monkeypatch.setitem(repo_scan._eslint_probe, "plugin_dir", "/usr/lib/node_modules")


def _ctx(langs, markers=None):
    return {"langs": Counter(langs), "markers": markers or {}, "req_files": [],
            "tf_dirs": [], "npm_dirs": []}


def _cmd(plan, tool):
    for entry in plan:
        if entry["tool"] == tool:
            return entry["command"]
    return ""


def _entry(plan, tool):
    for entry in plan:
        if entry["tool"] == tool:
            return entry
    return None


def test_semgrep_excludes_build_output(plan_env, tmp_path):
    cmd = _cmd(repo_scan._build_plan(_ctx({".ts": 40}), str(tmp_path), str(tmp_path), {}),
               "semgrep")
    assert cmd
    for name in (".next", "coverage", "node_modules"):
        assert f"--exclude {name}" in cmd or f"--exclude '{name}'" in cmd, name


def test_semgrep_excludes_minified_files(plan_env, tmp_path):
    """A committed bundle outside a build directory is still generated output."""
    cmd = _cmd(repo_scan._build_plan(_ctx({".js": 40}), str(tmp_path), str(tmp_path), {}),
               "semgrep")
    for pat in ("*.min.js", "*.bundle.js", "*.map"):
        assert pat in cmd, pat


# -- graudit's time limit --------------------------------------------------

def test_graudit_timeout_scales_with_the_tree():
    assert repo_scan._graudit_timeout(100) == repo_scan._FAST_TIMEOUT
    assert repo_scan._graudit_timeout(501) == repo_scan._TOOL_TIMEOUT
    assert repo_scan._graudit_timeout(2001) == repo_scan._SLOW_TIMEOUT
    assert repo_scan._graudit_timeout(4395) == repo_scan._SLOW_TIMEOUT


def test_graudit_on_a_large_repo_gets_more_than_the_fast_limit(plan_env, tmp_path):
    """rebot has 4,395 files and was killed at 300s."""
    big = _entry(repo_scan._build_plan(_ctx({".py": 4395}), str(tmp_path), str(tmp_path), {}),
                 "graudit")
    assert big is not None
    assert big["timeout"] > repo_scan._FAST_TIMEOUT
    small = _entry(repo_scan._build_plan(_ctx({".py": 20}), str(tmp_path), str(tmp_path), {}),
                   "graudit")
    assert small["timeout"] == repo_scan._FAST_TIMEOUT


# -- a cut-short pass must not read as a finished one ----------------------

def _fake_run(monkeypatch, timed_out, stdout="x"):
    monkeypatch.setattr(repo_scan, "execute_command",
                        lambda command, timeout=None: {
                            "return_code": -1 if timed_out else 0,
                            "timed_out": timed_out, "stdout": stdout, "stderr": "",
                            "duration": 1})


def test_a_timed_out_run_that_wrote_findings_is_marked_partial(monkeypatch, tmp_path):
    report = tmp_path / "graudit.json"
    report.write_text('{"findings": []}')
    monkeypatch.setattr(repo_scan, "_parse_findings", lambda r, t: {"findings": 279})
    _fake_run(monkeypatch, timed_out=True)

    out = repo_scan._run_tool("graudit", "graudit ...", str(report), 300)

    assert out["partial"] is True
    assert "279" in out["partial_reason"]
    assert "unproven" in out["partial_reason"]
    # the findings it did write are real, so they are kept
    assert out["findings"] == 279
    # and it is not reported as "no report written"
    assert "error" not in out


def test_a_cut_short_run_leaves_a_marker_beside_the_report(monkeypatch, tmp_path):
    report = tmp_path / "graudit.json"
    report.write_text("{}")
    monkeypatch.setattr(repo_scan, "_parse_findings", lambda r, t: {"findings": 5})
    _fake_run(monkeypatch, timed_out=True)

    repo_scan._run_tool("graudit", "graudit ...", str(report), 300)

    marker = tmp_path / "_cut_short.txt"
    assert marker.exists()
    body = marker.read_text()
    assert "graudit" in body and "300s" in body and "5 findings" in body


def test_the_marker_is_not_json(monkeypatch, tmp_path):
    """collect_stats.py globs *.json in this folder and would read a marker as a
    tool report, which is how a stale file became 3% of the W47 totals."""
    report = tmp_path / "graudit.json"
    report.write_text("{}")
    monkeypatch.setattr(repo_scan, "_parse_findings", lambda r, t: {"findings": 1})
    _fake_run(monkeypatch, timed_out=True)

    repo_scan._run_tool("graudit", "graudit ...", str(report), 300)

    assert sorted(p.name for p in tmp_path.glob("*.json")) == ["graudit.json"]


def test_a_finished_run_is_not_marked(monkeypatch, tmp_path):
    report = tmp_path / "semgrep.json"
    report.write_text("{}")
    monkeypatch.setattr(repo_scan, "_parse_findings", lambda r, t: {"findings": 3})
    _fake_run(monkeypatch, timed_out=False)

    out = repo_scan._run_tool("semgrep", "semgrep ...", str(report), 900)

    assert "partial" not in out
    assert not (tmp_path / "_cut_short.txt").exists()


def test_a_run_that_wrote_nothing_still_reports_the_error(monkeypatch, tmp_path):
    """The existing contract: no report means failure, not a clean scan."""
    _fake_run(monkeypatch, timed_out=True, stdout="")
    out = repo_scan._run_tool("graudit", "graudit ...", str(tmp_path / "missing.json"), 300)
    assert "no report written" in out["error"]
    assert "partial" not in out
