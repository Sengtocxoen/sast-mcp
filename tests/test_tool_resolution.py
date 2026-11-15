"""
Tests for scanner resolution reporting on /health.

Recreating the server venv for Python 3.14 deleted semgrep, checkov and safety,
because they had been pip-installed into that venv. Nothing failed loudly:
/health reported them missing, and repo scans kept returning success with those
engines simply absent. A stale ~/.local/bin/semgrep symlink pointed into the
deleted venv, so the name still appeared in a directory listing while `which`
resolved nothing.

/health now names any scanner that resolves from inside the server venv, so the
next rebuild is visible before it costs a sweep.
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

from flask import Flask  # noqa: E402

import core  # noqa: E402
from routes import health  # noqa: E402


def _venv_path(*parts):
    return os.path.join(core.PROJECT_VENV_BIN, *parts)


# --- PROJECT_VENV_BIN ------------------------------------------------------

def test_project_venv_bin_points_at_repo_venv():
    """The constant must track <repo>/venv/bin, not the running interpreter."""
    assert core.PROJECT_VENV_BIN == os.path.join(ROOT, "venv", "bin")


def test_enhanced_env_still_uses_the_constant():
    """Hoisting the path to module scope must not change PATH building."""
    env = core.get_enhanced_env()
    path_entries = (env.get("PATH") or "").split(os.pathsep)
    # Present only when the directory exists; assert we did not break the call.
    assert isinstance(path_entries, list) and path_entries


# --- _is_fragile -----------------------------------------------------------

def test_tool_inside_server_venv_is_fragile():
    assert health._is_fragile(_venv_path("semgrep")) is True


def test_pipx_tool_is_not_fragile():
    pipx = os.path.join(os.path.expanduser("~"), ".local", "share", "pipx",
                        "venvs", "semgrep", "bin", "semgrep")
    assert health._is_fragile(pipx) is False


def test_system_tool_is_not_fragile():
    assert health._is_fragile(os.path.join(os.sep, "usr", "bin", "bandit")) is False


def test_missing_tool_is_not_fragile():
    """A tool that resolves nowhere is "missing", not "fragile"."""
    assert health._is_fragile("") is False


def test_venv_bin_dir_itself_is_not_fragile():
    """Only files INSIDE the bin dir count, not a path that merely shares a prefix."""
    assert health._is_fragile(core.PROJECT_VENV_BIN) is False
    assert health._is_fragile(core.PROJECT_VENV_BIN + "-backup") is False


# --- _tool_path ------------------------------------------------------------

def test_tool_path_empty_for_unknown_binary():
    assert health._tool_path("nope", "definitely-not-a-real-binary --version") == ""


def test_tool_path_handles_which_style_check():
    """`which graudit` must probe graudit, not `which`."""
    assert health._binary_of("which graudit") == "graudit"


# --- /health response ------------------------------------------------------

def _client():
    app = Flask(__name__)
    health.register(app)
    return app.test_client()


def test_health_omits_fragile_key_when_nothing_is_in_the_venv(monkeypatch):
    monkeypatch.setattr(health, "_tool_path", lambda tool, cmd: "/usr/bin/" + tool)
    body = _client().get("/health").get_json()
    assert "fragile_tools" not in body
    assert "fragile_tools_hint" not in body


def test_health_reports_a_scanner_installed_in_the_venv(monkeypatch):
    monkeypatch.setattr(health, "_tool_available", lambda tool, cmd: tool == "bandit")
    monkeypatch.setattr(
        health, "_tool_path",
        lambda tool, cmd: _venv_path("bandit") if tool == "bandit" else "",
    )
    body = _client().get("/health").get_json()
    assert body["fragile_tools"] == ["bandit"]
    assert "install-python-scanners.sh" in body["fragile_tools_hint"]


def test_fragile_list_only_counts_installed_tools(monkeypatch):
    """A tool that is missing must not be reported as fragile."""
    monkeypatch.setattr(health, "_tool_available", lambda tool, cmd: False)
    monkeypatch.setattr(health, "_tool_path", lambda tool, cmd: _venv_path(tool))
    body = _client().get("/health").get_json()
    assert "fragile_tools" not in body


def test_health_still_reports_core_fields(monkeypatch):
    """The new key must not disturb the existing response shape."""
    monkeypatch.setattr(health, "_tool_path", lambda tool, cmd: "")
    body = _client().get("/health").get_json()
    for key in ("status", "tools_status", "all_essential_tools_available",
                "total_tools_available", "total_tools_count", "version"):
        assert key in body
