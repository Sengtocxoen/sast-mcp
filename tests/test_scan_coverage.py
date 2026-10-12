"""
Tests for the two coverage gaps found while auditing the 2026-08-07 estate sweep.

* Every TypeScript-only repo was scanned without `p/security-audit`. `.ts` and
  `.tsx` mapped to their language packs alone, while `.go`, `.py`, `.js`, `.rb`
  and `.java` all pulled the security pack in. TypeScript is the largest
  language in the estate (8,843 `.ts` + 3,716 `.tsx` files) and 23 of the 135
  scanned repos carry no `.js` at all, so for those the security rules never
  ran. deca-workflows-poc is one of them: semgrep reported 0 findings while a
  manual review found two CRITs, including an unsandboxed `new Function()`.

* eslint was dropped from 135 of 135 scans with no trace. The binary is
  installed and the language matches, but `_eslint_entry` returned a bare None
  when `eslint-plugin-security` was absent, so eslint appeared in neither
  `tools_planned` nor `tools_missing`. The only record was a log line, which is
  how the gap stayed hidden from June to October.

Each test below fails against the original code.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("USE_MULTIPROCESSING", "0")
os.environ.setdefault("MOUNT_POINT", ROOT)
os.environ.setdefault("WINDOWS_BASE", ROOT)
sys.path.insert(0, os.path.join(ROOT, "server"))

pytest.importorskip("flask", reason="flask not installed")

from collections import Counter  # noqa: E402

from routes import repo_scan  # noqa: E402


@pytest.fixture
def dest(monkeypatch, tmp_path):
    """Every tool installed, and no real subprocess probing."""
    monkeypatch.setattr(repo_scan.tool_registry, "have", lambda t: True)
    monkeypatch.setattr(repo_scan.tool_registry, "binary_for", lambda t: t)
    monkeypatch.setattr(repo_scan, "resolve_grep_engine", lambda: "semgrep")
    monkeypatch.setattr(repo_scan, "_grep_jobs_mem", lambda: (4, 2000))
    monkeypatch.setitem(repo_scan._eslint_probe, "major", 9)
    monkeypatch.setitem(repo_scan._eslint_probe, "plugin_dir", "/usr/lib/node_modules")
    return str(tmp_path)


def _ctx(langs):
    """The shape _detect_context returns, with no markers or lockfiles."""
    return {"langs": Counter(langs), "markers": {}, "req_files": [],
            "tf_dirs": [], "npm_dirs": []}


def _semgrep_cmd(plan):
    for entry in plan:
        if entry["tool"] == "semgrep":
            return entry["command"]
    return ""


def _tools(plan):
    return {entry["tool"] for entry in plan}


# -- the TypeScript ruleset gap --------------------------------------------

def test_ts_only_repo_gets_security_audit_pack(dest):
    plan = repo_scan._build_plan(_ctx({".ts": 42}), dest, dest, {})
    assert "p/security-audit" in _semgrep_cmd(plan)


def test_tsx_only_repo_gets_security_audit_pack(dest):
    plan = repo_scan._build_plan(_ctx({".tsx": 17}), dest, dest, {})
    assert "p/security-audit" in _semgrep_cmd(plan)


def test_ts_keeps_its_language_packs(dest):
    """The security pack is added to the TypeScript rules, not swapped for them."""
    cmd = _semgrep_cmd(repo_scan._build_plan(_ctx({".ts": 1}), dest, dest, {}))
    assert "p/typescript" in cmd
    assert "p/javascript" in cmd


def test_security_audit_is_not_duplicated_in_mixed_repo(dest):
    """A repo with both .ts and .js must not pass --config p/security-audit twice."""
    cmd = _semgrep_cmd(repo_scan._build_plan(_ctx({".ts": 5, ".js": 5}), dest, dest, {}))
    assert cmd.count("p/security-audit") == 1


# -- the silent-skip gap ----------------------------------------------------

def test_eslint_is_planned_when_the_plugin_is_present(dest):
    skips = {}
    plan = repo_scan._build_plan(_ctx({".ts": 5}), dest, dest, {}, skips)
    assert "eslint" in _tools(plan)
    assert "eslint" not in skips


def test_missing_eslint_plugin_is_recorded(dest, monkeypatch):
    monkeypatch.setitem(repo_scan._eslint_probe, "plugin_dir", "")
    skips = {}
    plan = repo_scan._build_plan(_ctx({".ts": 5}), dest, dest, {}, skips)
    assert "eslint" not in _tools(plan)
    assert "eslint-plugin-security" in skips["eslint"]


def test_undetectable_eslint_version_is_recorded(dest, monkeypatch):
    monkeypatch.setitem(repo_scan._eslint_probe, "major", 0)
    skips = {}
    repo_scan._build_plan(_ctx({".ts": 5}), dest, dest, {}, skips)
    assert "version" in skips["eslint"].lower()


def test_explicit_optout_is_recorded(dest):
    """A caller switching a tool off is a gap too, and must be distinguishable."""
    skips = {}
    plan = repo_scan._build_plan(_ctx({".go": 9}), dest, dest, {"gosec": False}, skips)
    assert "gosec" not in _tools(plan)
    assert "gosec" in skips


def test_skips_are_optional_for_existing_callers(dest):
    """Omitting the out-param must not break the old four-argument call."""
    assert repo_scan._build_plan(_ctx({".py": 3}), dest, dest, {})


# -- coverage must surface the skips ---------------------------------------

def test_coverage_surfaces_skipped_tools(dest, monkeypatch):
    monkeypatch.setattr(repo_scan.tool_registry, "availability",
                        lambda: {"semgrep": True, "eslint": True})
    reason = "eslint-plugin-security not installed"
    cov = repo_scan._coverage(_ctx({".ts": 5}), [{"tool": "semgrep"}], {"eslint": reason})
    assert cov["tools_skipped"] == {"eslint": reason}
    # The original defect: an installed-but-skipped tool was in neither list.
    assert "eslint" not in cov["tools_planned"]
    assert "eslint" not in cov["tools_missing"]


def test_coverage_skips_default_to_empty(dest, monkeypatch):
    monkeypatch.setattr(repo_scan.tool_registry, "availability", lambda: {"semgrep": True})
    cov = repo_scan._coverage(_ctx({".py": 1}), [{"tool": "semgrep"}])
    assert cov["tools_skipped"] == {}
